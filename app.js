const express = require('express');
const path = require('path');
const session = require('express-session');
const morgan = require('morgan');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const { ConfidentialClientApplication } = require('@azure/msal-node');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const ALLOWED_SSO_DOMAIN = 'mits.ac.in';
const SESSION_SECRET = (process.env.SESSION_SECRET || '').trim() || crypto.randomBytes(48).toString('hex');

if (!process.env.SESSION_SECRET) {
  // eslint-disable-next-line no-console
  console.warn('SESSION_SECRET is missing. Using temporary in-memory secret for this process.');
}

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const getMsalClient = () => {
  const clientId = (process.env.MS_CLIENT_ID || '').trim();
  const clientSecret = (process.env.MS_CLIENT_SECRET || '').trim();
  const tenantId = (process.env.MS_TENANT_ID || '').trim();
  const redirectUri = (process.env.MS_REDIRECT_URI || '').trim();

  if (!clientId || !clientSecret || !tenantId || !redirectUri) {
    return null;
  }

  return new ConfidentialClientApplication({
    auth: {
      clientId,
      authority: `https://login.microsoftonline.com/${tenantId}`,
      clientSecret,
    },
  });
};

const getSsoEmailFromClaims = (claims = {}) => {
  const candidates = [
    claims.preferred_username,
    claims.email,
    claims.upn,
  ];
  return candidates.find((v) => typeof v === 'string' && v.trim()) || '';
};

const resolveMsRedirectUri = (req) => {
  const configured = (process.env.MS_REDIRECT_URI || '').trim();
  if (configured && !configured.includes('localhost')) {
    return configured;
  }

  const host = req?.get?.('host') || '';
  const protocol = req?.protocol || 'https';
  if (host) {
    return `${protocol}://${host}/auth/microsoft/callback`;
  }

  return configured;
};

const requestRateStore = new Map();
const createSimpleRateLimiter = ({ keyPrefix, windowMs, maxRequests, errorMessage }) => (req, res, next) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  const key = `${keyPrefix}:${ip}`;
  const now = Date.now();
  const windowStart = now - windowMs;

  const existing = requestRateStore.get(key) || [];
  const recent = existing.filter((ts) => ts > windowStart);

  if (recent.length >= maxRequests) {
    return res.status(429).render('staffLogin', {
      error: errorMessage || 'Too many requests. Please try again later.',
    });
  }

  recent.push(now);
  requestRateStore.set(key, recent);
  return next();
};

const loginRateLimiter = createSimpleRateLimiter({
  keyPrefix: 'login',
  windowMs: 10 * 60 * 1000,
  maxRequests: 10,
  errorMessage: 'Too many login attempts. Please wait 10 minutes and try again.',
});

const ssoCallbackRateLimiter = createSimpleRateLimiter({
  keyPrefix: 'sso-callback',
  windowMs: 10 * 60 * 1000,
  maxRequests: 25,
  errorMessage: 'Too many Microsoft SSO attempts. Please wait 10 minutes and try again.',
});

const backgroundTaskState = new Map();
const HOD_BACKGROUND_TASKS = [
  { key: 'hod-reset-all-default', label: 'Reset all requests to default pending' },
  { key: 'hod-generate-all-requests', label: 'Generate all subject/objective requests' },
  { key: 'hod-generate-mentor-subjects', label: 'Generate mentor requests' },
  { key: 'hod-generate-objective-approvals', label: 'Generate objective approvals' },
];

const getBackgroundTaskSummaries = () => HOD_BACKGROUND_TASKS.map(({ key, label }) => {
  const state = backgroundTaskState.get(key) || {};
  const processed = Number.isFinite(state.processedItems) ? state.processedItems : 0;
  const total = Number.isFinite(state.totalItems) ? state.totalItems : 0;
  return {
    key,
    label,
    running: !!state.running,
    startedAt: state.startedAt || null,
    lastCompletedAt: state.lastCompletedAt || null,
    lastError: state.lastError || null,
    processedItems: processed,
    totalItems: total,
  };
});

const runBackgroundTask = (taskName, taskFn) => {
  const current = backgroundTaskState.get(taskName);
  if (current && current.running) {
    return false;
  }

  const nextState = {
    running: true,
    startedAt: Date.now(),
    lastCompletedAt: current?.lastCompletedAt || null,
    lastError: null,
    processedItems: 0,
    totalItems: Number.isFinite(current?.totalItems) ? current.totalItems : 0,
  };
  backgroundTaskState.set(taskName, nextState);

  const updateTaskState = (updater) => {
    const latest = backgroundTaskState.get(taskName) || nextState;
    const patch = typeof updater === 'function' ? updater(latest) : updater;
    backgroundTaskState.set(taskName, {
      ...latest,
      ...patch,
    });
  };

  setImmediate(async () => {
    try {
      const controller = {
        setTotal: (value) => {
          const safeTotal = Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
          updateTaskState({ totalItems: safeTotal });
        },
        setProcessed: (value) => {
          const safeProcessed = Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
          updateTaskState({ processedItems: safeProcessed });
        },
        incrementProcessed: (value = 1) => {
          const amount = Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
          updateTaskState((latest) => ({
            processedItems: (latest.processedItems || 0) + amount,
          }));
        },
      };

      await taskFn(controller);
      const latest = backgroundTaskState.get(taskName) || nextState;
      backgroundTaskState.set(taskName, {
        ...latest,
        running: false,
        lastCompletedAt: Date.now(),
        lastError: null,
      });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`Background task failed: ${taskName}`, err);
      const latest = backgroundTaskState.get(taskName) || nextState;
      backgroundTaskState.set(taskName, {
        ...latest,
        running: false,
        lastCompletedAt: Date.now(),
        lastError: err?.message || 'Unknown error',
      });
    }
  });

  return true;
};

const upload = multer({ storage: multer.memoryStorage() });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('dev'));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: 'auto',
    },
  }),
);

mongoose
  .connect(process.env.MONGO_URI, {
    dbName: 'nodue',
  })
  .then(async () => {
    // eslint-disable-next-line no-console
    console.log('Connected to MongoDB');

    // Best-effort cleanup of old unique index on subjectCode, if it exists
    try {
      const SubjectModel = mongoose.models.Subject;
      if (SubjectModel && SubjectModel.collection) {
        await SubjectModel.collection.dropIndex('subjectCode_1');
      }
    } catch (err) {
      if (err && err.codeName !== 'IndexNotFound') {
        // eslint-disable-next-line no-console
        console.error('Failed to drop legacy subjectCode index', err);
      }
    }

    // Best-effort cleanup: route legacy subject requests without faculty
    // to the HOD instead of exposing them to every faculty member.
    try {
      const hod = await Faculty.findOne({ role: 'hod' }).lean();
      if (hod && hod.facultyId) {
        await Request.updateMany(
          {
            subjectCode: { $nin: [null, ''] },
            $or: [
              { facultyId: null },
              { facultyId: { $exists: false } },
              { facultyId: '' },
            ],
          },
          { $set: { facultyId: hod.facultyId } },
        );
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to backfill subject request faculty', err);
    }
  })
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error('MongoDB connection error', err);
  });

const studentSchema = new mongoose.Schema(
  {
    rollNumber: { type: String, required: true, unique: true, trim: true },
    name: { type: String, required: true, trim: true },
    branch: { type: String, trim: true },
    department: { type: String, trim: true },
    year: { type: String, trim: true },
    section: { type: String, trim: true },
    semester: { type: String, trim: true },
    mentorFacultyId: { type: String, trim: true },
    mentorNotes: { type: String, trim: true },
  },
  { timestamps: true },
);

studentSchema.index({ rollNumber: 1 }, { unique: true });
const Student = mongoose.model('Student', studentSchema);

const facultySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    facultyId: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    department: { type: String, required: true, trim: true },
    role: { type: String, enum: ['faculty', 'hod'], default: 'faculty' },
  },
  { timestamps: true },
);

facultySchema.index({ facultyId: 1 }, { unique: true });
const Faculty = mongoose.model('Faculty', facultySchema);

const subjectSchema = new mongoose.Schema(
  {
    // Subject code is no longer globally unique; it can repeat across branches
    subjectCode: { type: String, required: true, trim: true },
    subjectName: { type: String, required: true, trim: true },
    // Single owning branch for this subject offering
    branch: { type: String, trim: true },
    // Optional historical support for multi-branch subjects (not used for new records)
    branches: [{ type: String, trim: true }],
    year: { type: String, trim: true },
    semester: { type: String, trim: true },
    // Single faculty per subject offering (stored as array for compatibility)
    facultyIds: [{ type: String, trim: true }],
    // Section-specific faculty assignments: [{section: "A", facultyId: "FAC101"}, ...]
    sectionFaculty: [
      {
        section: { type: String, trim: true },
        facultyId: { type: String, trim: true },
      },
    ],
  },
  { timestamps: true },
);

// Enforce uniqueness per subject offering: same code can repeat across branches
subjectSchema.index({ subjectCode: 1, branch: 1 }, { unique: true });
const Subject = mongoose.model('Subject', subjectSchema);

// Mentor-level generic subjects (objectives) common to all mentors
const mentorSubjectSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true, trim: true },
    name: { type: String, required: true, trim: true },
    years: [{ type: String, trim: true }],
  },
  { timestamps: true },
);

const MentorSubject = mongoose.model('MentorSubject', mentorSubjectSchema);

// Objective approvals (e.g., NASSCOM): one faculty approval per student per objective
const objectiveApprovalSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true, trim: true },
    name: { type: String, required: true, trim: true },
    facultyId: { type: String, required: true, trim: true },
    years: [{ type: String, trim: true }],
  },
  { timestamps: true },
);

const ObjectiveApproval = mongoose.model('ObjectiveApproval', objectiveApprovalSchema);

// HOD final approval per student (tracks final sign-off by HOD)
const hodApprovalSchema = new mongoose.Schema(
  {
    rollNumber: { type: String, trim: true, index: true },
    studentName: { type: String, trim: true },
    approved: { type: Boolean, default: false },
    approvedBy: { type: String, trim: true },
    approvedAt: { type: Date },
  },
  { timestamps: true },
);

const HODApproval = mongoose.model('HODApproval', hodApprovalSchema);
// Request schema: persists all clearance/assignment requests
const requestSchema = new mongoose.Schema(
  {
    rollNumber: { type: String, required: true, index: true },
    studentName: { type: String, trim: true },
    subjectCode: { type: String, trim: true },
    subjectName: { type: String, trim: true },
    facultyId: { type: String, trim: true },
    department: { type: String, trim: true },
    branch: { type: String, trim: true },
    year: { type: String, trim: true },
    semester: { type: String, trim: true },
    section: { type: String, trim: true },
    reason: { type: String, trim: true },
    status: { type: String, default: 'Pending Faculty' },
    assignment1: { type: Boolean, default: false },
    assignment2: { type: Boolean, default: false },
    facultyNote: { type: String, trim: true },
    adminNote: { type: String, trim: true },
  },
  { timestamps: true },
);

const Request = mongoose.model('Request', requestSchema);

let cachedHodFacultyId = null;
const getFallbackFacultyId = async (preferredFacultyId = null) => {
  if (preferredFacultyId) return preferredFacultyId;
  if (cachedHodFacultyId !== null) return cachedHodFacultyId || null;

  try {
    const hod = await Faculty.findOne({ role: 'hod' }).lean();
    cachedHodFacultyId = hod && hod.facultyId ? hod.facultyId : '';
    return cachedHodFacultyId || null;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to resolve fallback faculty', err);
    cachedHodFacultyId = '';
    return null;
  }
};

const isMentorRequest = (request) => {
  const reason = request?.reason || '';
  const subjectCode = request?.subjectCode || '';
  return (
    reason.startsWith('Mentor objective:')
    || reason.startsWith('Mentor objectives:')
    || subjectCode.startsWith('MENTOR::')
  );
};

const isObjectiveRequest = (request) => {
  const reason = request?.reason || '';
  const subjectCode = request?.subjectCode || '';
  return reason.startsWith('Objective approval:') || subjectCode.startsWith('OBJECTIVE::');
};

const isStudentInApplicableYears = (studentYear, allowedYears) => {
  if (!Array.isArray(allowedYears) || !allowedYears.length) return true;
  const sy = normalizeYearToken(studentYear);
  if (!sy) return false;
  const allowed = allowedYears
    .map((y) => normalizeYearToken(y))
    .filter(Boolean);
  return allowed.includes(sy);
};

const normalizeYearToken = (value) => {
  const raw = (value || '').toString().trim().toUpperCase();
  if (!raw) return '';
  if (['I', '1', '1ST', 'FIRST'].includes(raw)) return '1';
  if (['II', '2', '2ND', 'SECOND'].includes(raw)) return '2';
  if (['III', '3', '3RD', 'THIRD'].includes(raw)) return '3';
  if (['IV', '4', '4TH', 'FOURTH'].includes(raw)) return '4';
  return raw;
};

const compareRollNumbers = (a, b) => {
  const left = (a || '').toString().trim().toUpperCase();
  const right = (b || '').toString().trim().toUpperCase();
  return left.localeCompare(right, undefined, { numeric: false, sensitivity: 'base' });
};

const compareLabels = (a, b) => {
  const left = (a || '').toString().trim();
  const right = (b || '').toString().trim();
  return left.localeCompare(right, undefined, { numeric: true, sensitivity: 'base' });
};

const compareAcademicYear = (a, b) => {
  const left = normalizeYearToken(a);
  const right = normalizeYearToken(b);
  const leftNum = Number(left);
  const rightNum = Number(right);

  if (!Number.isNaN(leftNum) && !Number.isNaN(rightNum)) {
    return leftNum - rightNum;
  }
  return compareLabels(left, right);
};

const compareApprovalRows = (a, b) => {
  const yearDiff = compareAcademicYear(a.year, b.year);
  if (yearDiff !== 0) return yearDiff;
  const sectionDiff = compareLabels(a.section, b.section);
  if (sectionDiff !== 0) return sectionDiff;
  const deptDiff = compareLabels(a.department, b.department);
  if (deptDiff !== 0) return deptDiff;
  return compareRollNumbers(a.rollNumber, b.rollNumber);
};

const countUniqueStudents = (rows = []) => {
  const unique = new Set();
  rows.forEach((row) => {
    const roll = (row?.rollNumber || '').toString().trim().toUpperCase();
    if (roll) unique.add(roll);
  });
  return unique.size;
};

const statusBucketForApproval = (row, options = {}) => {
  const status = (row?.status || '').toString().trim();
  const approvedByAssignments = !!(row?.assignment1 && row?.assignment2);
  const approved = status === 'Approved' || (options.useAssignmentPair && approvedByAssignments);
  if (approved) return 'approved';

  if (
    ['Rejected by Faculty', 'Rejected by HOD', 'Denied', 'Rejected'].includes(status)
  ) {
    return 'denied';
  }

  return 'pending';
};

const buildFacultyAnalytics = ({
  generalRequests = [],
  subjectRequests = [],
  mentorSubjectRequests = [],
  objectiveRequests = [],
}) => {
  const categories = [
    {
      key: 'subject',
      label: 'Subject approvals',
      rows: subjectRequests,
      options: { useAssignmentPair: true },
    },
    {
      key: 'mentor',
      label: 'Mentor approvals',
      rows: mentorSubjectRequests,
      options: { useAssignmentPair: true },
    },
    {
      key: 'objective',
      label: 'Objective approvals',
      rows: objectiveRequests,
      options: { useAssignmentPair: true },
    },
    {
      key: 'general',
      label: 'General approvals',
      rows: generalRequests,
      options: { useAssignmentPair: false },
    },
  ].map((category) => {
    const totals = category.rows.reduce(
      (acc, row) => {
        const bucket = statusBucketForApproval(row, category.options);
        acc[bucket] += 1;
        if ((row?.status || '').toString().trim() === 'Pending Faculty') {
          acc.actionablePending += 1;
        }
        return acc;
      },
      {
        approved: 0,
        pending: 0,
        denied: 0,
        actionablePending: 0,
      },
    );

    const total = category.rows.length;
    const approvalRate = total ? Math.round((totals.approved / total) * 100) : 0;

    return {
      key: category.key,
      label: category.label,
      total,
      students: countUniqueStudents(category.rows),
      approved: totals.approved,
      pending: totals.pending,
      denied: totals.denied,
      actionablePending: totals.actionablePending,
      approvalRate,
    };
  });

  const overall = categories.reduce(
    (acc, item) => ({
      total: acc.total + item.total,
      students: acc.students + item.students,
      approved: acc.approved + item.approved,
      pending: acc.pending + item.pending,
      denied: acc.denied + item.denied,
      actionablePending: acc.actionablePending + item.actionablePending,
    }),
    {
      total: 0,
      students: 0,
      approved: 0,
      pending: 0,
      denied: 0,
      actionablePending: 0,
    },
  );

  const overallApprovalRate = overall.total ? Math.round((overall.approved / overall.total) * 100) : 0;

  return {
    categories,
    overall: {
      ...overall,
      approvalRate: overallApprovalRate,
    },
  };
};

const buildHodAnalytics = ({ allRequests = [] }) => {
  const subjectRequests = allRequests.filter(
    (r) => r.subjectCode && !isMentorRequest(r) && !isObjectiveRequest(r),
  );
  const mentorRequests = allRequests.filter((r) => isMentorRequest(r));
  const objectiveRequests = allRequests.filter((r) => isObjectiveRequest(r));
  const generalRequests = allRequests.filter(
    (r) => !r.subjectCode && !isMentorRequest(r) && !isObjectiveRequest(r),
  );

  const categorySeed = [
    { key: 'subject', label: 'Subject approvals', rows: subjectRequests },
    { key: 'mentor', label: 'Mentor approvals', rows: mentorRequests },
    { key: 'objective', label: 'Objective approvals', rows: objectiveRequests },
    { key: 'general', label: 'General approvals', rows: generalRequests },
  ];

  const categories = categorySeed.map((category) => {
    const totals = category.rows.reduce(
      (acc, row) => {
        const status = (row?.status || '').toString().trim();

        if (status === 'Approved') {
          acc.approved += 1;
        } else if (['Rejected by Faculty', 'Rejected by HOD', 'Denied', 'Rejected'].includes(status)) {
          acc.denied += 1;
        } else {
          acc.pending += 1;
        }

        if (status === 'Pending HOD') acc.pendingHod += 1;
        if (status === 'Pending Faculty') acc.pendingFaculty += 1;
        return acc;
      },
      {
        approved: 0,
        pending: 0,
        denied: 0,
        pendingHod: 0,
        pendingFaculty: 0,
      },
    );

    const total = category.rows.length;
    const approvalRate = total ? Math.round((totals.approved / total) * 100) : 0;

    return {
      key: category.key,
      label: category.label,
      total,
      students: countUniqueStudents(category.rows),
      approved: totals.approved,
      pending: totals.pending,
      denied: totals.denied,
      pendingHod: totals.pendingHod,
      pendingFaculty: totals.pendingFaculty,
      approvalRate,
    };
  });

  const overall = categories.reduce(
    (acc, item) => ({
      total: acc.total + item.total,
      students: acc.students + item.students,
      approved: acc.approved + item.approved,
      pending: acc.pending + item.pending,
      denied: acc.denied + item.denied,
      pendingHod: acc.pendingHod + item.pendingHod,
      pendingFaculty: acc.pendingFaculty + item.pendingFaculty,
    }),
    {
      total: 0,
      students: 0,
      approved: 0,
      pending: 0,
      denied: 0,
      pendingHod: 0,
      pendingFaculty: 0,
    },
  );

  const overallApprovalRate = overall.total ? Math.round((overall.approved / overall.total) * 100) : 0;

  return {
    categories,
    overall: {
      ...overall,
      approvalRate: overallApprovalRate,
    },
  };
};

const buildStudentsByDepartmentYearSection = (students = [], allRequests = [], hodApprovals = []) => {
  const deptMap = new Map();

  students.forEach((student) => {
    const dept = (student.department || student.branch || 'Unassigned').toString().trim();
    const year = (student.year || 'No Year').toString().trim();
    const section = (student.section || 'No Section').toString().trim();

    if (!deptMap.has(dept)) {
      deptMap.set(dept, new Map());
    }
    const yearMap = deptMap.get(dept);

    if (!yearMap.has(year)) {
      yearMap.set(year, new Map());
    }
    const sectionMap = yearMap.get(year);

    if (!sectionMap.has(section)) {
      sectionMap.set(section, []);
    }
    sectionMap.get(section).push(student);
  });

  // Calculate approval status for each student
  const requestsByRoll = new Map();
  allRequests.forEach((req) => {
    const roll = (req.rollNumber || '').trim().toUpperCase();
    if (!requestsByRoll.has(roll)) {
      requestsByRoll.set(roll, []);
    }
    requestsByRoll.get(roll).push(req);
  });

  const getStudentApprovalStatus = (student) => {
    const roll = (student.rollNumber || '').trim().toUpperCase();
    const reqs = requestsByRoll.get(roll) || [];
    
    if (!reqs.length) return 'No Requests';
    
    const nonMentorNonObjective = reqs.filter((r) => !isMentorRequest(r) && !isObjectiveRequest(r));
    const mentorReqs = reqs.filter((r) => isMentorRequest(r));
    const objectiveReqs = reqs.filter((r) => isObjectiveRequest(r));
    
    const allApproved = (arr) => arr.length === 0 || arr.every((r) => r.status === 'Approved');
    
    const nonMentorStatus = allApproved(nonMentorNonObjective) ? 'approved' : 'pending';
    const mentorStatus = allApproved(mentorReqs) ? 'approved' : 'pending';
    const objectiveStatus = allApproved(objectiveReqs) ? 'approved' : 'pending';
    
    const statuses = [];
    if (nonMentorNonObjective.length > 0) statuses.push(nonMentorStatus);
    if (mentorReqs.length > 0) statuses.push(mentorStatus);
    if (objectiveReqs.length > 0) statuses.push(objectiveStatus);
    
    if (statuses.length === 0) return 'No Requests';
    if (statuses.every((s) => s === 'approved')) return 'Approved';
    return 'Pending';
  };

  const result = Array.from(deptMap.entries())
    .sort((a, b) => compareLabels(a[0], b[0]))
    .map(([dept, yearMap]) => ({
      department: dept,
      years: Array.from(yearMap.entries())
        .sort((a, b) => compareAcademicYear(a[0], b[0]))
        .map(([year, sectionMap]) => ({
          year,
          sections: Array.from(sectionMap.entries())
            .sort((a, b) => compareLabels(a[0], b[0]))
            .map(([section, sectionStudents]) => ({
              section,
              students: sectionStudents
                .sort((a, b) => compareRollNumbers(a.rollNumber, b.rollNumber))
                .map((student) => ({
                  ...student,
                  approvalStatus: getStudentApprovalStatus(student),
                  // attach HOD final approval info if available
                  hodApproval: (Array.isArray(hodApprovals) ? (hodApprovals.find((h) => {
                    const hr = (h.rollNumber || '').trim().toUpperCase();
                    const sr = (student.rollNumber || '').trim().toUpperCase();
                    const hn = (h.studentName || '').trim().toLowerCase();
                    const sn = (student.name || '').trim().toLowerCase();
                    return (hr && hr === sr) || (hn && sn && hn === sn);
                  }) || null) : null),
                })),
            })),
        })),
    }));

  return result;
};

const groupMentorRequestsByYearSectionDepartment = (rows = []) => {
  const subjectMap = new Map();

  rows.forEach((row) => {
    const subjectCode = (row.subjectCode || '').toString().trim();
    const subjectName = (row.subjectName || row.reason || 'General Mentor Subject').toString().trim();
    const subjectKey = subjectCode || subjectName;
    const year = (row.year || '').toString().trim() || 'No Year';
    const section = (row.section || '').toString().trim() || 'No Section';
    const department = (row.department || '').toString().trim() || 'Unassigned Department';

    if (!subjectMap.has(subjectKey)) {
      subjectMap.set(subjectKey, {
        subjectCode,
        subjectName,
        years: new Map(),
      });
    }

    const subjectGroup = subjectMap.get(subjectKey);
    const yearMap = subjectGroup.years;
    if (!yearMap.has(year)) {
      yearMap.set(year, new Map());
    }

    const sectionMap = yearMap.get(year);
    if (!sectionMap.has(section)) {
      sectionMap.set(section, new Map());
    }

    const normalizedDeptMap = sectionMap.get(section);
    if (!normalizedDeptMap.has(department)) {
      normalizedDeptMap.set(department, []);
    }

    normalizedDeptMap.get(department).push(row);
  });

  return Array.from(subjectMap.values())
    .sort((a, b) => compareLabels(a.subjectName || a.subjectCode, b.subjectName || b.subjectCode))
    .map((subjectGroup) => ({
      subjectCode: subjectGroup.subjectCode,
      subjectName: subjectGroup.subjectName,
      years: Array.from(subjectGroup.years.entries())
        .sort((a, b) => compareAcademicYear(a[0], b[0]))
        .map(([year, sectionMap]) => ({
          year,
          sections: Array.from(sectionMap.entries())
            .sort((a, b) => compareLabels(a[0], b[0]))
            .map(([section, sectionRows]) => ({
              section,
              departments: Array.from(sectionRows.entries())
                .sort((a, b) => compareLabels(a[0], b[0]))
                .map(([department, departmentRows]) => ({
                  department,
                  rows: departmentRows.slice().sort(compareApprovalRows),
                })),
            })),
        })),
    }));
};

const groupRowsByYearSectionDepartment = (rows = []) => {
  const yearMap = new Map();

  rows.forEach((row) => {
    const year = (row.year || '').toString().trim() || 'No Year';
    const section = (row.section || '').toString().trim() || 'No Section';
    const department = (row.department || '').toString().trim() || 'Unassigned Department';

    if (!yearMap.has(year)) {
      yearMap.set(year, new Map());
    }

    const sectionMap = yearMap.get(year);
    if (!sectionMap.has(section)) {
      sectionMap.set(section, new Map());
    }

    const departmentMap = sectionMap.get(section);
    if (!departmentMap.has(department)) {
      departmentMap.set(department, []);
    }

    departmentMap.get(department).push(row);
  });

  return Array.from(yearMap.entries())
    .sort((a, b) => compareAcademicYear(a[0], b[0]))
    .map(([year, sectionMap]) => ({
      year,
      sections: Array.from(sectionMap.entries())
        .sort((a, b) => compareLabels(a[0], b[0]))
        .map(([section, sectionRows]) => ({
          section,
          departments: Array.from(sectionRows.entries())
            .sort((a, b) => compareLabels(a[0], b[0]))
            .map(([department, departmentRows]) => ({
              department,
              rows: departmentRows.slice().sort(compareApprovalRows),
            })),
        })),
    }));
};

const pickBestMentorRequest = (rows = []) => {
  if (!Array.isArray(rows) || !rows.length) return null;

  const priority = (status) => {
    switch (status) {
      case 'Approved':
        return 5;
      case 'Rejected by Faculty':
      case 'Rejected by HOD':
        return 4;
      case 'Pending HOD':
        return 3;
      case 'Pending Faculty':
        return 2;
      default:
        return 1;
    }
  };

  return rows
    .slice()
    .sort((a, b) => {
      const pDiff = priority(b?.status) - priority(a?.status);
      if (pDiff !== 0) return pDiff;
      return new Date(b?.updatedAt || 0).getTime() - new Date(a?.updatedAt || 0).getTime();
    })[0];
};

const HOD_DASHBOARD_PANELS = new Set([
  'hod-subject-data',
  'hod-mentee-data',
  'student-list-by-department',
  'student-approval-detail',
  'manage-students',
  'manage-faculty',
  'manage-subjects',
  'manage-mentors',
  'manage-objective-approvals',
  'profile',
]);

const redirectToHodPanel = (req, fallbackPanel = 'hod-subject-data') => {
  const requested = (req.body?.redirectPanel || '').toString().trim();
  const panel = HOD_DASHBOARD_PANELS.has(requested) ? requested : fallbackPanel;
  return `/hod#${panel}`;
};

const isStudentInObjectiveYears = (studentYear, objectiveYears) => isStudentInApplicableYears(studentYear, objectiveYears);

const ensureObjectiveRequestsForObjective = async (objective) => {
  if (!objective || !objective.code || !objective.facultyId) return;

  try {
    const students = await Student.find().lean();
    if (!students.length) return;

    const objectiveCode = `OBJECTIVE::${objective.code}`;
    const reason = `Objective approval: ${objective.code}`;

    const targetStudents = students.filter((stu) => isStudentInObjectiveYears(stu.year, objective.years));
    if (!targetStudents.length) return;

    const rollNumbers = targetStudents.map((s) => s.rollNumber);
    const existing = await Request.find({
      rollNumber: { $in: rollNumbers },
      subjectCode: objectiveCode,
    }).lean();
    const existingByRoll = new Map(existing.map((r) => [r.rollNumber, r]));

    for (const stu of targetStudents) {
      const existingRow = existingByRoll.get(stu.rollNumber);
      const facultyChanged = existingRow && existingRow.facultyId !== objective.facultyId;

      const setPayload = {
        rollNumber: stu.rollNumber,
        studentName: stu.name,
        subjectCode: objectiveCode,
        subjectName: objective.name,
        facultyId: objective.facultyId,
        department: stu.department || stu.branch || '',
        branch: stu.branch || '',
        year: stu.year || '',
        semester: stu.semester || '',
        section: stu.section || '',
        reason,
      };

      if (!existingRow || facultyChanged) {
        setPayload.status = 'Pending Faculty';
        setPayload.assignment1 = false;
        setPayload.assignment2 = false;
        setPayload.facultyNote = '';
        setPayload.adminNote = '';
      }

      // eslint-disable-next-line no-await-in-loop
      await Request.findOneAndUpdate(
        { rollNumber: stu.rollNumber, subjectCode: objectiveCode },
        { $set: setPayload },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      );
    }

    // Remove stale requests for students no longer in applicable years.
    const staleRolls = students
      .filter((stu) => !isStudentInObjectiveYears(stu.year, objective.years))
      .map((stu) => stu.rollNumber);
    if (staleRolls.length) {
      await Request.deleteMany({ rollNumber: { $in: staleRolls }, subjectCode: objectiveCode });
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to ensure objective requests', err);
  }
};

const ensureObjectiveRequestsForAllStudents = async () => {
  try {
    const objectives = await ObjectiveApproval.find().lean();
    for (const objective of objectives) {
      // eslint-disable-next-line no-await-in-loop
      await ensureObjectiveRequestsForObjective(objective);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to ensure all objective requests', err);
  }
};

const ensureObjectiveRequestsForStudent = async (student) => {
  if (!student || !student.rollNumber) return;
  try {
    const objectives = await ObjectiveApproval.find().lean();
    for (const objective of objectives) {
      const objectiveCode = `OBJECTIVE::${objective.code}`;
      if (!isStudentInObjectiveYears(student.year, objective.years)) {
        // eslint-disable-next-line no-await-in-loop
        await Request.deleteOne({ rollNumber: student.rollNumber, subjectCode: objectiveCode });
        // eslint-disable-next-line no-continue
        continue;
      }

      // eslint-disable-next-line no-await-in-loop
      await Request.findOneAndUpdate(
        { rollNumber: student.rollNumber, subjectCode: objectiveCode },
        {
          $setOnInsert: {
            rollNumber: student.rollNumber,
            studentName: student.name,
            subjectCode: objectiveCode,
            subjectName: objective.name,
            facultyId: objective.facultyId,
            department: student.department || student.branch || '',
            branch: student.branch || '',
            year: student.year || '',
            semester: student.semester || '',
            section: student.section || '',
            reason: `Objective approval: ${objective.code}`,
            status: 'Pending Faculty',
            assignment1: false,
            assignment2: false,
            facultyNote: '',
            adminNote: '',
          },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      );
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to ensure objective requests for student', err);
  }
};

const loadObjectiveInfoForStudent = async (student) => {
  if (!student || !student.rollNumber) return null;

  try {
    const objectives = await ObjectiveApproval.find().sort({ createdAt: 1 }).lean();
    if (!objectives.length) return null;

    const applicableObjectives = objectives.filter((obj) => isStudentInObjectiveYears(student.year, obj.years));
    if (!applicableObjectives.length) return null;

    const objectiveCodes = applicableObjectives.map((obj) => `OBJECTIVE::${obj.code}`);
    const objectiveRequests = await Request.find({
      rollNumber: student.rollNumber,
      subjectCode: { $in: objectiveCodes },
    }).lean();
    const objectiveRequestMap = new Map(objectiveRequests.map((r) => [r.subjectCode, r]));

    const facultyIds = Array.from(
      new Set(applicableObjectives.map((obj) => obj.facultyId).filter(Boolean)),
    );
    const facultyMap = new Map();
    if (facultyIds.length) {
      const facs = await Faculty.find({ facultyId: { $in: facultyIds } }).lean();
      facs.forEach((f) => facultyMap.set(f.facultyId, f.name));
    }

    const objectivesView = applicableObjectives.map((obj) => {
      const req = objectiveRequestMap.get(`OBJECTIVE::${obj.code}`);
      const status = req && req.status ? req.status : 'Pending Faculty';
      const approved = status === 'Approved' || !!(req && req.assignment1);
      return {
        code: obj.code,
        name: obj.name,
        facultyId: obj.facultyId,
        facultyName: facultyMap.get(obj.facultyId) || null,
        status,
        approved,
        facultyNote: req && req.facultyNote ? req.facultyNote : '',
      };
    });

    const overallStatus = objectivesView.every((obj) => obj.approved) ? 'Approved' : 'Pending Faculty';

    return {
      status: overallStatus,
      objectives: objectivesView,
    };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load objective info for student', err);
    return null;
  }
};

// Ensure that for a given subject, all relevant students have a Request row
const ensureRequestsForSubject = async (subject) => {
  if (!subject) return;

  const { subjectCode, subjectName, branch, branches, year, semester, facultyIds, sectionFaculty } = subject;

  // Support mapping a subject to one or many branches
  const branchList = Array.isArray(branches) && branches.length
    ? branches.filter(Boolean)
    : (branch ? [branch] : []);

  if (!subjectCode || !branchList.length || !year || !semester) return;

  try {
    const students = await Student.find({ branch: { $in: branchList }, year, semester }).lean();
    if (!students.length) return;

    const rollNumbers = students.map((s) => s.rollNumber);

    const existing = await Request.find({
      subjectCode,
      rollNumber: { $in: rollNumbers },
    }).lean();

    const existingKeys = new Set(existing.map((r) => `${r.rollNumber}`));
    const defaultFacultyId =
      Array.isArray(facultyIds) && facultyIds.length ? facultyIds[0] : null;
    const fallbackFacultyId = await getFallbackFacultyId(defaultFacultyId);

    // Build a map of section → facultyId for quick lookup
    const sectionFacultyMap = new Map();
    if (Array.isArray(sectionFaculty) && sectionFaculty.length) {
      sectionFaculty.forEach(({ section, facultyId }) => {
        if (section && facultyId) {
          sectionFacultyMap.set(section.trim(), facultyId.trim());
        }
      });
    }

    const toInsert = [];
    students.forEach((stu) => {
      if (!existingKeys.has(stu.rollNumber)) {
        // Check if there's a section-specific faculty assignment
        let assignedFacultyId = fallbackFacultyId;
        if (stu.section && sectionFacultyMap.has(stu.section)) {
          assignedFacultyId = sectionFacultyMap.get(stu.section);
        }

        toInsert.push({
          rollNumber: stu.rollNumber,
          studentName: stu.name,
          subjectCode,
          subjectName,
          facultyId: assignedFacultyId,
          department: stu.department || stu.branch || '',
          branch: stu.branch || '',
          year: stu.year || '',
          semester: stu.semester || '',
          section: stu.section || '',
          reason: `No-due clearance for ${subjectName}`,
          status: 'Pending Faculty',
          assignment1: false,
          assignment2: false,
          facultyNote: '',
          adminNote: '',
        });
      }
    });

    if (toInsert.length) {
      await Request.insertMany(toInsert);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to ensure requests for subject', err);
  }
};

// Ensure mentor no-due requests exist for all students mapped to a given mentor faculty
const ensureMentorRequestsForFaculty = async (facultyId) => {
  if (!facultyId) return;

  const fallbackReason = 'Mentor objectives: Achievements & Mentoring feedback';

  try {
    const students = await Student.find({ mentorFacultyId: facultyId }).lean();
    if (!students.length) return;

    const mentorSubjects = await MentorSubject.find().sort({ code: 1 }).lean();
    const hasMentorSubjects = Array.isArray(mentorSubjects) && mentorSubjects.length > 0;

    for (const stu of students) {
      const base = {
        rollNumber: stu.rollNumber,
        studentName: stu.name,
        facultyId,
        department: stu.department || stu.branch || '',
        branch: stu.branch || '',
        year: stu.year || '',
        semester: stu.semester || '',
        section: stu.section || '',
      };

      const applicableMentorSubjects = mentorSubjects.filter((mentorSubject) =>
        isStudentInApplicableYears(stu.year, mentorSubject.years),
      );

      if (hasMentorSubjects) {
        if (applicableMentorSubjects.length) {
          for (const mentorSubject of applicableMentorSubjects) {
            const mentorSubjectCode = `MENTOR::${mentorSubject.code}`;
            const mentorReason = `Mentor objective: ${mentorSubject.code}`;

            // eslint-disable-next-line no-await-in-loop
            await Request.findOneAndUpdate(
              {
                rollNumber: stu.rollNumber,
                facultyId,
                subjectCode: mentorSubjectCode,
                reason: mentorReason,
              },
              {
                ...base,
                subjectCode: mentorSubjectCode,
                subjectName: mentorSubject.name,
                reason: mentorReason,
                status: 'Pending Faculty',
              },
              { upsert: true, new: true, setDefaultsOnInsert: true },
            );
          }

          // Remove fallback rows once specific mentor-subject requests exist.
          // eslint-disable-next-line no-await-in-loop
          await Request.deleteOne({
            rollNumber: stu.rollNumber,
            facultyId,
            subjectCode: { $in: [null, ''] },
            reason: fallbackReason,
          });
        } else {
          // No mentor subject applies to this student's year; keep one fallback mentor request.
          // eslint-disable-next-line no-await-in-loop
          await Request.findOneAndUpdate(
            {
              rollNumber: stu.rollNumber,
              facultyId,
              subjectCode: { $in: [null, ''] },
              reason: fallbackReason,
            },
            {
              ...base,
              subjectCode: null,
              subjectName: null,
              reason: fallbackReason,
              status: 'Pending Faculty',
            },
            { upsert: true, new: true, setDefaultsOnInsert: true },
          );
        }

        const inapplicableMentorSubjects = mentorSubjects.filter(
          (mentorSubject) => !isStudentInApplicableYears(stu.year, mentorSubject.years),
        );
        for (const mentorSubject of inapplicableMentorSubjects) {
          // eslint-disable-next-line no-await-in-loop
          await Request.deleteOne({
            rollNumber: stu.rollNumber,
            facultyId,
            subjectCode: `MENTOR::${mentorSubject.code}`,
          });
        }
      } else {
        // Backward-compatible fallback when no mentor subjects are defined.
        // eslint-disable-next-line no-await-in-loop
        await Request.findOneAndUpdate(
          {
            rollNumber: stu.rollNumber,
            facultyId,
            subjectCode: { $in: [null, ''] },
            reason: fallbackReason,
          },
          {
            ...base,
            subjectCode: null,
            subjectName: null,
            reason: fallbackReason,
            status: 'Pending Faculty',
          },
          { upsert: true, new: true, setDefaultsOnInsert: true },
        );
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to ensure mentor requests for faculty', err);
  }
};

// Keep Request.facultyId in sync with the subject's assigned faculty
const syncSubjectRequestsFaculty = async (subject) => {
  if (!subject) return;

  const { subjectCode, branch, year, semester, facultyIds, sectionFaculty } = subject;
  const defaultFacultyId =
    Array.isArray(facultyIds) && facultyIds.length ? facultyIds[0] : null;
  const fallbackFacultyId = await getFallbackFacultyId(defaultFacultyId);

  if (!subjectCode || !fallbackFacultyId) return;

  const filter = { subjectCode };
  if (branch) filter.branch = branch;
  if (year) filter.year = year;
  if (semester) filter.semester = semester;

  try {
    // Build a map of section → facultyId for quick lookup
    const sectionFacultyMap = new Map();
    if (Array.isArray(sectionFaculty) && sectionFaculty.length) {
      sectionFaculty.forEach(({ section, facultyId }) => {
        if (section && facultyId) {
          sectionFacultyMap.set(section.trim(), facultyId.trim());
        }
      });
    }

    const mappedSections = Array.from(sectionFacultyMap.keys());

    // If there are section-specific faculty assignments, update per section
    if (sectionFacultyMap.size > 0) {
      // Update requests for each section with its specific faculty
      for (const [section, facultyId] of sectionFacultyMap.entries()) {
        // eslint-disable-next-line no-await-in-loop
        await Request.updateMany(
          { ...filter, section },
          { $set: { facultyId } },
        );
      }
    }

    // Update only requests that do not have a section-specific mapping
    await Request.updateMany(
      {
        ...filter,
        $or: [
          { section: { $exists: false } },
          { section: null },
          { section: '' },
          ...(mappedSections.length ? [{ section: { $nin: mappedSections } }] : []),
        ],
      },
      { $set: { facultyId: fallbackFacultyId } },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to sync subject request faculty', err);
  }
};

// CASCADE: When faculty ID is updated, cascade to all related requests and students
const cascadeFacultyIdUpdate = async (oldFacultyId, newFacultyId) => {
  if (!oldFacultyId || !newFacultyId || oldFacultyId === newFacultyId) return;

  try {
    // Update all requests assigned to this faculty
    await Request.updateMany(
      { facultyId: oldFacultyId },
      { $set: { facultyId: newFacultyId } },
    );

    // Update all students mentored by this faculty
    await Student.updateMany(
      { mentorFacultyId: oldFacultyId },
      { $set: { mentorFacultyId: newFacultyId } },
    );

    // Update objective approval mappings owned by this faculty
    await ObjectiveApproval.updateMany(
      { facultyId: oldFacultyId },
      { $set: { facultyId: newFacultyId } },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to cascade faculty ID update', err);
  }
};

// CASCADE: When subject code is updated, cascade to all related requests
const cascadeSubjectCodeUpdate = async (oldSubjectCode, newSubjectCode, oldBranch) => {
  if (!oldSubjectCode || !newSubjectCode || oldSubjectCode === newSubjectCode) return;

  try {
    // Find old subject to get branch and other info
    const filter = { subjectCode: oldSubjectCode };
    if (oldBranch) filter.branch = oldBranch;

    // Update all requests with the old subject code to new code
    await Request.updateMany(
      { subjectCode: oldSubjectCode, ...(oldBranch ? { branch: oldBranch } : {}) },
      { $set: { subjectCode: newSubjectCode } },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to cascade subject code update', err);
  }
};

// CASCADE: When subject name is updated, cascade to all related requests
const cascadeSubjectNameUpdate = async (subjectCode, newSubjectName, branch) => {
  if (!subjectCode || !newSubjectName) return;

  try {
    const filter = { subjectCode };
    if (branch) filter.branch = branch;

    // Update all requests with this subject code to have new name
    await Request.updateMany(filter, { $set: { subjectName: newSubjectName } });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to cascade subject name update', err);
  }
};

// CASCADE: When student data is updated, cascade to all their requests
const cascadeStudentDataUpdate = async (rollNumber, studentName) => {
  if (!rollNumber || !studentName) return;

  try {
    // Update all requests for this student with new name
    await Request.updateMany(
      { rollNumber },
      { $set: { studentName } },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to cascade student data update', err);
  }
};

app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

const ensureRole = (...roles) => (req, res, next) => {
  const user = req.session.user;
  if (!user || !roles.includes(user.role)) {
    return res.redirect('/login');
  }
  return next();
};

const loadCurrentFaculty = async (req) => {
  if (!req.session.user || !req.session.user.facultyId) return null;
  try {
    return await Faculty.findOne({ facultyId: req.session.user.facultyId }).lean();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load faculty profile', err);
    return null;
  }
};

const renderFacultyDashboard = async (req, res, extras = {}) => {
  const self = await loadCurrentFaculty(req);
  if (!self) {
    return res.status(404).render('staffLogin', { error: 'Profile not found. Please log in again.' });
  }

  // Auto-sync mentor requests for newly added mentor subjects
  try {
    await ensureMentorRequestsForFaculty(self.facultyId);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to sync mentor requests for faculty dashboard', err);
  }

  // Load requests for this faculty from DB
  let myRequests = [];
  try {
    myRequests = await Request.find({
      $or: [
        { facultyId: self.facultyId },
        { facultyId: { $exists: false } },
        { facultyId: null },
      ],
    })
      .sort({ createdAt: -1 })
      .lean();

    // decorate with id for templates
    myRequests = myRequests.map((r) => ({ ...r, id: r._id.toString() }));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load faculty requests', err);
  }

  let assignedMentees = [];
  try {
    assignedMentees = await Student.find({ mentorFacultyId: self.facultyId }).sort({ rollNumber: 1 }).lean();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load assigned mentees', err);
  }

  // Split into subject-based vs general requests
  const subjectRequests = myRequests.filter(
    (r) => r.subjectCode && !isMentorRequest(r) && !isObjectiveRequest(r),
  );
  const generalRequests = myRequests.filter(
    (r) => !r.subjectCode && !isMentorRequest(r) && !isObjectiveRequest(r),
  );

  // Mentor-specific objectives and mentor-subject requests
  const mentorRequests = myRequests.filter((r) => isMentorRequest(r));
  const mentorSubjectRequests = mentorRequests
    .filter((r) => (r.subjectCode || '').startsWith('MENTOR::'))
    .slice()
    .sort(compareApprovalRows);
  const objectiveRequests = myRequests.filter((r) => isObjectiveRequest(r));
  const mentorSubjectRequestGroups = groupMentorRequestsByYearSectionDepartment(mentorSubjectRequests);
  const facultyAnalytics = buildFacultyAnalytics({
    generalRequests,
    subjectRequests,
    mentorSubjectRequests,
    objectiveRequests,
  });

  // Mentor subjects used for labelling mentor objective toggles
  let mentorSubjects = [];
  try {
    mentorSubjects = await MentorSubject.find().sort({ code: 1 }).lean();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load mentor subjects', err);
  }

  let objectiveApprovals = [];
  try {
    objectiveApprovals = await ObjectiveApproval.find({ facultyId: self.facultyId }).sort({ name: 1 }).lean();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load objective approvals', err);
  }

  const objectiveRequestMap = new Map();
  objectiveRequests.forEach((r) => {
    const key = (r.subjectCode || '').trim() || (r.subjectName || '').trim();
    if (!objectiveRequestMap.has(key)) {
      objectiveRequestMap.set(key, []);
    }
    objectiveRequestMap.get(key).push(r);
  });

  const objectiveGroups = objectiveApprovals.map((objective) => {
    const code = `OBJECTIVE::${objective.code}`;
    const rows = (objectiveRequestMap.get(code) || []).slice().sort(compareApprovalRows);
    return {
      code: objective.code,
      name: objective.name,
      facultyId: objective.facultyId,
      years: objective.years || [],
      rows,
      groupedRows: groupRowsByYearSectionDepartment(rows),
    };
  });

  // Include any objective requests not linked to a current objective definition,
  // so older records still remain visible.
  objectiveRequests.forEach((r) => {
    const key = (r.subjectCode || '').trim() || (r.subjectName || '').trim();
    if (objectiveApprovals.some((obj) => `OBJECTIVE::${obj.code}` === key)) return;
    if (objectiveGroups.some((g) => g.code === key)) return;
    objectiveGroups.push({
      code: key,
      name: r.subjectName || r.reason || 'Objective',
      facultyId: r.facultyId || self.facultyId,
      years: [],
      rows: (objectiveRequestMap.get(key) || []).slice().sort(compareApprovalRows),
      groupedRows: groupRowsByYearSectionDepartment((objectiveRequestMap.get(key) || []).slice().sort(compareApprovalRows)),
    });
  });

  // Group subject-wise for tabular display (like approval sheets)
  const subjectGroupsMap = new Map();
  subjectRequests.forEach((r) => {
    const key = r.subjectCode || r.subjectName || 'Unknown';
    if (!subjectGroupsMap.has(key)) {
      subjectGroupsMap.set(key, {
        subjectCode: r.subjectCode || '',
        subjectName: r.subjectName || 'Unknown Subject',
        rows: [],
      });
    }
    subjectGroupsMap.get(key).rows.push(r);
  });

  // Convert to array and sort subjects and rows by roll number
  const subjectGroups = Array.from(subjectGroupsMap.values())
    .sort((a, b) => (a.subjectCode || '').localeCompare(b.subjectCode || ''));

  subjectGroups.forEach((group) => {
    group.rows.sort(compareApprovalRows);
  });

  const payload = {
    // Pending approvals should exclude mentor objective requests,
    // which are handled separately in the Mentees data panel.
    pending: generalRequests.filter(
      (r) => r.status === 'Pending Faculty',
    ),
    all: generalRequests,
    mentorRequests,
    mentorSubjectRequests,
    mentorSubjectRequestGroups,
    objectiveRequests,
    objectiveApprovals,
    objectiveGroups,
    mentorSubjects,
    subjectGroups,
    facultyAnalytics,
    assignedMentees,
    self,
    profileError: extras.profileError || null,
    profileSuccess: extras.profileSuccess || null,
  };

  return res.render('facultyDashboard', payload);
};

const renderHodDashboard = async (req, res, extras = {}) => {
  const self = await loadCurrentFaculty(req);
  if (!self) {
    return res.status(404).render('staffLogin', { error: 'Profile not found. Please log in again.' });
  }

  try {
    await ensureMentorRequestsForFaculty(self.facultyId);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to sync mentor requests for HOD dashboard', err);
  }

  // Load subject-wise requests for this HOD acting strictly as assigned faculty
  let subjectGroups = [];
  let hodSubjectGroups = [];
  try {
    let myRequests = await Request.find({
      facultyId: self.facultyId,
    })
      .sort({ createdAt: -1 })
      .lean();

    myRequests = myRequests.map((r) => ({ ...r, id: r._id.toString() }));

    // Mentor requests are handled in the dedicated mentee approvals panel (button flow only).
    const subjectRequests = myRequests.filter(
      (r) => r.subjectCode && !isMentorRequest(r) && !isObjectiveRequest(r),
    );

    const subjectGroupsMap = new Map();
    subjectRequests.forEach((r) => {
      const key = r.subjectCode || r.subjectName || 'Unknown';
      if (!subjectGroupsMap.has(key)) {
        subjectGroupsMap.set(key, {
          subjectCode: r.subjectCode || '',
          subjectName: r.subjectName || 'Unknown Subject',
          rows: [],
        });
      }
      subjectGroupsMap.get(key).rows.push(r);
    });

    subjectGroups = Array.from(subjectGroupsMap.values()).sort((a, b) =>
      (a.subjectCode || '').localeCompare(b.subjectCode || ''),
    );

    subjectGroups.forEach((group) => {
      group.rows.sort(compareApprovalRows);
    });

    hodSubjectGroups = subjectGroups.map((group) => {
      const pendingRows = group.rows.filter((r) => r.status !== 'Approved');
      return {
        ...group,
        pendingRows: pendingRows.slice().sort(compareApprovalRows),
        pendingCount: pendingRows.length,
        totalCount: group.rows.length,
      };
    }).sort((a, b) => (a.subjectCode || '').localeCompare(b.subjectCode || ''));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load HOD subject-wise requests', err);
  }

  let students = [];
  let faculties = [];
  let subjects = [];
  let mentorSubjects = [];
  let objectiveApprovals = [];
  let dataError = null;
  let pendingRequests = [];
  let allRequests = [];
  let pendingSubjectGroups = [];
  let pendingMentorRequests = [];
  let hodMentorRequests = [];

  try {
    students = await Student.find().sort({ rollNumber: 1 }).lean();
    faculties = await Faculty.find().sort({ facultyId: 1 }).lean();
    subjects = await Subject.find().sort({ subjectCode: 1 }).lean();
    mentorSubjects = await MentorSubject.find().sort({ code: 1 }).lean();
    objectiveApprovals = await ObjectiveApproval.find().sort({ createdAt: 1 }).lean();

    allRequests = await Request.find().sort({ createdAt: -1 }).lean();
    allRequests = allRequests.map((r) => ({ ...r, id: r._id.toString() }));
    pendingRequests = allRequests.filter(
      (r) => r.status === 'Pending HOD' && !isMentorRequest(r) && !isObjectiveRequest(r),
    );
    pendingMentorRequests = pendingRequests.filter((r) => {
      return isMentorRequest(r);
    });
    hodMentorRequests = allRequests.filter((r) => {
      return r.facultyId === self.facultyId && isMentorRequest(r);
    }).sort(compareApprovalRows);

    const pendingSubjectMap = new Map();
    pendingRequests.forEach((r) => {
      const key = (r.subjectCode || '').trim() || 'GENERAL';
      if (!pendingSubjectMap.has(key)) {
        pendingSubjectMap.set(key, {
          subjectCode: key === 'GENERAL' ? '' : key,
          subjectName: r.subjectName || (key === 'GENERAL' ? 'General Requests' : 'Unknown Subject'),
          rows: [],
        });
      }
      pendingSubjectMap.get(key).rows.push(r);
    });

    pendingSubjectGroups = Array.from(pendingSubjectMap.values()).sort((a, b) =>
      (a.subjectCode || '').localeCompare(b.subjectCode || ''),
    );

    pendingSubjectGroups.forEach((group) => {
      group.rows.sort((a, b) => {
        const ra = (a.rollNumber || '').toString();
        const rb = (b.rollNumber || '').toString();
        return ra.localeCompare(rb);
      });
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load HOD data', err);
    dataError = 'Could not load all records right now.';
  }

  const hodAnalytics = buildHodAnalytics({ allRequests });
  // load HOD final approvals to annotate students
  let hodApprovals = [];
  try {
    hodApprovals = await HODApproval.find().lean();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load HOD approvals', err);
  }

  const studentsByDepartmentYearSection = buildStudentsByDepartmentYearSection(students, allRequests, hodApprovals);

  const payload = {
    pending: pendingRequests,
    all: allRequests,
    pendingMentorRequests,
    hodMentorRequests,
    hodMentorRequestGroups: groupMentorRequestsByYearSectionDepartment(hodMentorRequests),
    students,
    studentsByDepartmentYearSection,
    faculties,
    subjects,
    mentorSubjects,
    objectiveApprovals,
    self,
    subjectGroups,
    hodSubjectGroups,
    hodAnalytics,
    pendingSubjectGroups,
    dataError,
    hodBackgroundTasks: getBackgroundTaskSummaries(),
    profileError: extras.profileError || null,
    profileSuccess: extras.profileSuccess || null,
    initialPanel: extras.initialPanel || null,
  };

  return res.render('HODDashboard', payload);
};

app.get('/', (req, res) => {
  const user = req.session.user;
  if (user && user.role === 'faculty') {
    return res.redirect('/faculty');
  }
  if (user && user.role === 'hod') {
    return res.redirect('/hod');
  }
  return res.render('login', { error: null, searchError: null, searchResult: null });
});

app.get('/login', (req, res) => {
  const user = req.session.user;
  if (user && user.role === 'faculty') {
    return res.redirect('/faculty');
  }
  if (user && user.role === 'hod') {
    return res.redirect('/hod');
  }
  return res.render('staffLogin', { error: null });
});

app.get('/auth/microsoft', async (req, res) => {
  const msalClient = getMsalClient();
  if (!msalClient) {
    return res.status(500).render('staffLogin', {
      error: 'Microsoft SSO is not configured. Contact administrator.',
    });
  }

  try {
    const state = crypto.randomBytes(16).toString('hex');
    req.session.msAuthState = state;

    const authCodeUrl = await msalClient.getAuthCodeUrl({
      scopes: ['openid', 'profile', 'email', 'User.Read'],
      redirectUri: resolveMsRedirectUri(req),
      state,
      prompt: 'select_account',
    });

    return res.redirect(authCodeUrl);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to start Microsoft SSO', err);
    return res.status(500).render('staffLogin', {
      error: 'Could not start Microsoft sign-in. Please try again.',
    });
  }
});

app.get('/auth/microsoft/callback', ssoCallbackRateLimiter, async (req, res) => {
  const msalClient = getMsalClient();
  if (!msalClient) {
    return res.status(500).render('staffLogin', {
      error: 'Microsoft SSO is not configured. Contact administrator.',
    });
  }

  const receivedState = (req.query.state || '').toString();
  const expectedState = (req.session.msAuthState || '').toString();
  req.session.msAuthState = null;

  if (!receivedState || !expectedState || receivedState !== expectedState) {
    return res.status(400).render('staffLogin', {
      error: 'Invalid SSO state. Please try signing in again.',
    });
  }

  const authCode = (req.query.code || '').toString();
  if (!authCode) {
    return res.status(400).render('staffLogin', {
      error: 'Microsoft sign-in failed. Authorization code missing.',
    });
  }

  try {
    const tokenResponse = await msalClient.acquireTokenByCode({
      code: authCode,
      scopes: ['openid', 'profile', 'email', 'User.Read'],
      redirectUri: resolveMsRedirectUri(req),
    });

    const claims = tokenResponse?.idTokenClaims || {};
    const email = getSsoEmailFromClaims(claims).trim();
    const lowerEmail = email.toLowerCase();

    if (!email || !lowerEmail.endsWith(`@${ALLOWED_SSO_DOMAIN}`)) {
      return res.status(403).render('staffLogin', {
        error: `Only @${ALLOWED_SSO_DOMAIN} accounts are allowed.`,
      });
    }

    const facultyIdPrefix = lowerEmail.split('@')[0];
    const faculty = await Faculty.findOne({
      facultyId: { $regex: `^${escapeRegex(facultyIdPrefix)}$`, $options: 'i' },
    }).lean();

    if (!faculty) {
      return res.status(403).render('staffLogin', {
        error: 'No staff account found for this Microsoft email prefix.',
      });
    }

    const role = faculty.role || 'faculty';
    req.session.user = {
      name: faculty.name,
      facultyId: faculty.facultyId,
      role,
      email,
    };

    return res.redirect(role === 'hod' ? '/hod' : '/faculty');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Microsoft SSO callback failed', err);
    return res.status(500).render('staffLogin', {
      error: 'Microsoft sign-in failed. Please try again.',
    });
  }
});

app.post('/login', loginRateLimiter, async (req, res) => {
  try {
    const staffId = (req.body.staffId || '').trim();
    const password = (req.body.password || '').trim();
    if (!staffId || !password) {
      return res
        .status(400)
        .render('staffLogin', {
          error: 'Staff ID and password are required for faculty / HOD.',
        });
    }

    const faculty = await Faculty.findOne({
      facultyId: { $regex: `^${escapeRegex(staffId)}$`, $options: 'i' },
    }).lean();
    if (!faculty) {
      return res
        .status(401)
        .render('staffLogin', { error: 'Invalid staff credentials.' });
    }

    const validPassword = await bcrypt.compare(password, faculty.password);
    if (!validPassword) {
      return res
        .status(401)
        .render('staffLogin', { error: 'Invalid staff credentials.' });
    }

    const role = faculty.role || 'faculty';
    req.session.user = { name: faculty.name, facultyId: faculty.facultyId, role };
    return res.redirect(role === 'hod' ? '/hod' : '/faculty');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Login failed', err);
    return res.status(500).render('staffLogin', {
      error: 'Could not sign in right now. Please try again.',
    });
  }
});

app.post('/student/search', async (req, res) => {
  const rollNumber = (req.body.rollNumber || '').trim();
  if (!rollNumber) {
    return res.status(400).render('login', {
      error: null,
      searchError: 'Roll number is required to search.',
      searchResult: null,
    });
  }

  try {
    const student = await Student.findOne({
      rollNumber: { $regex: `^${escapeRegex(rollNumber)}$`, $options: 'i' },
    }).lean();
    if (!student) {
      return res.status(404).render('login', {
        error: null,
        searchError: 'No student found for this roll number.',
        searchResult: null,
      });
    }

    const subjectFilter = {
      year: student.year || undefined,
      semester: student.semester || undefined,
    };

    if (student.branch) {
      subjectFilter.$or = [
        { branch: student.branch },
        { branches: student.branch },
      ];
    }

    const subjects = await Subject.find(subjectFilter)
      .sort({ subjectCode: 1 })
      .lean();

    // Ensure there is a clearance request for each subject registered by this student
    const subjectCodes = subjects.map((s) => s.subjectCode);

    const existingRequests = await Request.find({
      rollNumber,
      subjectCode: { $in: subjectCodes },
    }).lean();

    const existingByCode = new Map(existingRequests.map((r) => [r.subjectCode, r]));

    const newRequests = [];
    for (const subj of subjects) {
      if (!existingByCode.has(subj.subjectCode)) {
        // Prefer subject default faculty; otherwise route to HOD (not all faculty)
        const facultyId = await getFallbackFacultyId(
          Array.isArray(subj.facultyIds) && subj.facultyIds.length ? subj.facultyIds[0] : null,
        );
        newRequests.push({
          rollNumber,
          studentName: student.name,
          subjectCode: subj.subjectCode,
          subjectName: subj.subjectName,
          facultyId,
          department: student.department || student.branch || '',
          branch: student.branch || '',
          year: student.year || '',
          semester: student.semester || '',
          section: student.section || '',
          reason: `No-due clearance for ${subj.subjectName}`,
          status: 'Pending Faculty',
          assignment1: false,
          assignment2: false,
          facultyNote: '',
          adminNote: '',
        });
      }
    }

    if (newRequests.length) {
      await Request.insertMany(newRequests);
    }

    const allRequests = await Request.find({
      rollNumber: student.rollNumber,
      subjectCode: { $in: subjectCodes },
    }).lean();

    const requestsByCode = new Map(allRequests.map((r) => [r.subjectCode, r]));

    const facultyIds = Array.from(
      new Set(
        allRequests
          .map((r) => r.facultyId)
          .filter(Boolean),
      ),
    );
    const facultyMap = new Map();
    if (facultyIds.length) {
      const facs = await Faculty.find({ facultyId: { $in: facultyIds } }).lean();
      facs.forEach((f) => {
        facultyMap.set(f.facultyId, f.name);
      });
    }

    const subjectStatuses = subjects.map((subj) => {
      const match = requestsByCode.get(subj.subjectCode);
      const assignment1 = !!(match && match.assignment1);
      const assignment2 = !!(match && match.assignment2);
      const facultyName = match && match.facultyId ? facultyMap.get(match.facultyId) : null;

      return {
        subjectCode: subj.subjectCode,
        subjectName: subj.subjectName,
        assignment1,
        assignment2,
        facultyName,
        facultyNote: match && match.facultyNote ? match.facultyNote : '',
      };
    });

    // Mentor information for this student
    let mentorInfo = null;
    let mentorSubjects = [];
    try {
      mentorSubjects = await MentorSubject.find().sort({ code: 1 }).lean();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to load mentor subjects for student view', err);
    }

    const applicableMentorSubjects = mentorSubjects.filter((m) => isStudentInApplicableYears(student.year, m.years));
    const mentorSubjectCodes = applicableMentorSubjects.map((m) => `MENTOR::${m.code}`);
    const mentorSubjectRequests = mentorSubjectCodes.length
      ? await Request.find({
        rollNumber,
        subjectCode: { $in: mentorSubjectCodes },
      }).lean()
      : [];

    const mentorRequestsByCode = new Map();
    mentorSubjectRequests.forEach((r) => {
      const code = r.subjectCode || '';
      if (!mentorRequestsByCode.has(code)) mentorRequestsByCode.set(code, []);
      mentorRequestsByCode.get(code).push(r);
    });
    const mentorRequestMap = new Map();
    mentorRequestsByCode.forEach((rows, code) => {
      mentorRequestMap.set(code, pickBestMentorRequest(rows));
    });

    // Legacy fallback for older mentor-request format
    const mentorReason = 'Mentor objectives: Achievements & Mentoring feedback';
    const legacyMentorRequest = await Request.findOne({
      rollNumber,
      subjectCode: { $in: [null, ''] },
      reason: mentorReason,
    }).lean();

    const firstMentorRequest = pickBestMentorRequest(mentorSubjectRequests) || legacyMentorRequest || null;
    const hasMentorMapping = !!(student.mentorFacultyId || firstMentorRequest);

    if (hasMentorMapping) {
      const mentorFacultyId =
        (firstMentorRequest && firstMentorRequest.facultyId) || student.mentorFacultyId || null;
      let mentorName = null;
      if (mentorFacultyId) {
        const mentor = await Faculty.findOne({ facultyId: mentorFacultyId }).lean();
        mentorName = mentor ? mentor.name : null;
      }

      const objectives = applicableMentorSubjects.map((ms) => {
        const reqForObjective = mentorRequestMap.get(`MENTOR::${ms.code}`);
        const status = reqForObjective && reqForObjective.status
          ? reqForObjective.status
          : 'Pending Faculty';
        const approved = status === 'Approved'
          || !!(reqForObjective && reqForObjective.assignment1 && reqForObjective.assignment2);
        return {
          code: ms.code,
          name: ms.name,
          status,
          approved,
          facultyNote: reqForObjective && reqForObjective.facultyNote ? reqForObjective.facultyNote : '',
        };
      });

      // Legacy fallback for old two-toggle mentor record if no mentor-subject objectives exist.
      if (!objectives.length && legacyMentorRequest) {
        objectives.push(
          {
            code: 'LEGACY-1',
            name: 'Achievements approved',
            status: legacyMentorRequest.assignment1 ? 'Approved' : 'Pending Faculty',
            approved: !!legacyMentorRequest.assignment1,
            facultyNote: legacyMentorRequest.facultyNote || '',
          },
          {
            code: 'LEGACY-2',
            name: 'Mentoring feedback',
            status: legacyMentorRequest.assignment2 ? 'Approved' : 'Pending Faculty',
            approved: !!legacyMentorRequest.assignment2,
            facultyNote: legacyMentorRequest.facultyNote || '',
          },
        );
      }

      let overallStatus = 'Pending Faculty';
      if (objectives.length && objectives.every((o) => o.approved)) {
        overallStatus = 'Approved';
      } else if (objectives.some((o) => (o.status || '').startsWith('Rejected'))) {
        overallStatus = 'Rejected by Faculty';
      }

      const firstObjective = objectives[0] || null;
      const secondObjective = objectives[1] || null;

      mentorInfo = {
        mentorFacultyId,
        mentorName,
        label1: firstObjective ? firstObjective.name : 'Achievements approved',
        label2: secondObjective ? secondObjective.name : 'Mentoring feedback',
        assignment1: firstObjective ? !!firstObjective.approved : false,
        assignment2: secondObjective ? !!secondObjective.approved : false,
        facultyNote: (firstMentorRequest && firstMentorRequest.facultyNote) || '',
        status: overallStatus,
        objectives,
      };
    }

    const objectiveInfo = await loadObjectiveInfoForStudent(student);

    // Load HOD final-approval for this student (by roll or name)
    let hodApproval = null;
    try {
      hodApproval = await HODApproval.findOne({ rollNumber: student.rollNumber }).lean();
      if (!hodApproval) {
        hodApproval = await HODApproval.findOne({ studentName: student.name }).lean();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to load HOD approval for login student view', err);
    }

    return res.render('login', {
      error: null,
      searchError: null,
      searchResult: {
        rollNumber,
        student,
        subjects: subjectStatuses,
        mentorInfo,
        objectiveInfo,
        hodApproval,
      },
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Student search failed', err);
    return res.status(500).render('login', {
      error: null,
      searchError: 'Unable to fetch status right now. Please try again.',
      searchResult: null,
    });
  }
});

// AJAX endpoint for student to poll their approval status (used for auto-refresh)
app.post('/api/student/search-status', async (req, res) => {
  const rollNumber = (req.body.rollNumber || '').trim();
  if (!rollNumber) {
    return res.status(400).json({ error: 'Roll number is required.' });
  }

  try {
    const student = await Student.findOne({
      rollNumber: { $regex: `^${escapeRegex(rollNumber)}$`, $options: 'i' },
    }).lean();
    if (!student) {
      return res.status(404).json({ error: 'Student not found.' });
    }

    const subjectFilter = {
      year: student.year || undefined,
      semester: student.semester || undefined,
    };

    if (student.branch) {
      subjectFilter.$or = [
        { branch: student.branch },
        { branches: student.branch },
      ];
    }

    const subjects = await Subject.find(subjectFilter).sort({ subjectCode: 1 }).lean();
    const subjectCodes = subjects.map((s) => s.subjectCode);

    const allRequests = await Request.find({
      rollNumber: student.rollNumber,
      subjectCode: { $in: subjectCodes },
    }).lean();

    const requestsByCode = new Map(allRequests.map((r) => [r.subjectCode, r]));

    const facultyIds = Array.from(
      new Set(
        allRequests
          .map((r) => r.facultyId)
          .filter(Boolean),
      ),
    );
    const facultyMap = new Map();
    if (facultyIds.length) {
      const facs = await Faculty.find({ facultyId: { $in: facultyIds } }).lean();
      facs.forEach((f) => {
        facultyMap.set(f.facultyId, f.name);
      });
    }

    const subjectStatuses = subjects.map((subj) => {
      const match = requestsByCode.get(subj.subjectCode);
      const assignment1 = !!(match && match.assignment1);
      const assignment2 = !!(match && match.assignment2);
      const facultyName = match && match.facultyId ? facultyMap.get(match.facultyId) : null;

      return {
        subjectCode: subj.subjectCode,
        subjectName: subj.subjectName,
        assignment1,
        assignment2,
        facultyName,
        facultyNote: match && match.facultyNote ? match.facultyNote : '',
      };
    });

    // Mentor information for this student
    let mentorInfo = null;
    let mentorSubjects = [];
    try {
      mentorSubjects = await MentorSubject.find().sort({ code: 1 }).lean();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to load mentor subjects for student view', err);
    }

    const applicableMentorSubjects = mentorSubjects.filter((m) => isStudentInApplicableYears(student.year, m.years));
    const mentorSubjectCodes = applicableMentorSubjects.map((m) => `MENTOR::${m.code}`);
    const mentorSubjectRequests = mentorSubjectCodes.length
      ? await Request.find({
        rollNumber,
        subjectCode: { $in: mentorSubjectCodes },
      }).lean()
      : [];

    const mentorRequestsByCode = new Map();
    mentorSubjectRequests.forEach((r) => {
      const code = r.subjectCode || '';
      if (!mentorRequestsByCode.has(code)) mentorRequestsByCode.set(code, []);
      mentorRequestsByCode.get(code).push(r);
    });
    const mentorRequestMap = new Map();
    mentorRequestsByCode.forEach((rows, code) => {
      mentorRequestMap.set(code, pickBestMentorRequest(rows));
    });

    // Legacy fallback for older mentor-request format
    const mentorReason = 'Mentor objectives: Achievements & Mentoring feedback';
    const legacyMentorRequest = await Request.findOne({
      rollNumber,
      subjectCode: { $in: [null, ''] },
      reason: mentorReason,
    }).lean();

    const firstMentorRequest = pickBestMentorRequest(mentorSubjectRequests) || legacyMentorRequest || null;
    const hasMentorMapping = !!(student.mentorFacultyId || firstMentorRequest);

    if (hasMentorMapping) {
      const mentorFacultyId =
        (firstMentorRequest && firstMentorRequest.facultyId) || student.mentorFacultyId || null;
      let mentorName = null;
      if (mentorFacultyId) {
        const mentor = await Faculty.findOne({ facultyId: mentorFacultyId }).lean();
        mentorName = mentor ? mentor.name : null;
      }

      const objectives = applicableMentorSubjects.map((ms) => {
        const reqForObjective = mentorRequestMap.get(`MENTOR::${ms.code}`);
        const status = reqForObjective && reqForObjective.status
          ? reqForObjective.status
          : 'Pending Faculty';
        const approved = status === 'Approved'
          || !!(reqForObjective && reqForObjective.assignment1 && reqForObjective.assignment2);
        return {
          code: ms.code,
          name: ms.name,
          status,
          approved,
          facultyNote: reqForObjective && reqForObjective.facultyNote ? reqForObjective.facultyNote : '',
        };
      });

      // Legacy fallback for old two-toggle mentor record if no mentor-subject objectives exist.
      if (!objectives.length && legacyMentorRequest) {
        objectives.push(
          {
            code: 'LEGACY-1',
            name: 'Achievements approved',
            status: legacyMentorRequest.assignment1 ? 'Approved' : 'Pending Faculty',
            approved: !!legacyMentorRequest.assignment1,
            facultyNote: legacyMentorRequest.facultyNote || '',
          },
          {
            code: 'LEGACY-2',
            name: 'Mentoring feedback',
            status: legacyMentorRequest.assignment2 ? 'Approved' : 'Pending Faculty',
            approved: !!legacyMentorRequest.assignment2,
            facultyNote: legacyMentorRequest.facultyNote || '',
          },
        );
      }

      let overallStatus = 'Pending Faculty';
      if (objectives.length && objectives.every((o) => o.approved)) {
        overallStatus = 'Approved';
      } else if (objectives.some((o) => (o.status || '').startsWith('Rejected'))) {
        overallStatus = 'Rejected by Faculty';
      }

      const firstObjective = objectives[0] || null;
      const secondObjective = objectives[1] || null;

      mentorInfo = {
        mentorFacultyId,
        mentorName,
        label1: firstObjective ? firstObjective.name : 'Achievements approved',
        label2: secondObjective ? secondObjective.name : 'Mentoring feedback',
        assignment1: firstObjective ? !!firstObjective.approved : false,
        assignment2: secondObjective ? !!secondObjective.approved : false,
        facultyNote: (firstMentorRequest && firstMentorRequest.facultyNote) || '',
        status: overallStatus,
        objectives,
      };
    }

    const objectiveInfo = await loadObjectiveInfoForStudent(student);

    return res.json({
      rollNumber,
      student,
      subjects: subjectStatuses,
      mentorInfo,
      objectiveInfo,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Student search API failed', err);
    return res.status(500).json({ error: 'Unable to fetch status right now. Please try again.' });
  }
});

app.get('/faculty/profile', ensureRole('faculty'), async (req, res) =>
  renderFacultyDashboard(req, res, { profileError: null, profileSuccess: null }),
);

app.post('/faculty/profile', ensureRole('faculty'), async (req, res) => {
  const current = await loadCurrentFaculty(req);
  if (!current) {
    return res.status(404).render('staffLogin', {
      error: 'Profile not found. Please log in again.',
    });
  }

  const name = (req.body.name || '').trim();
  const newFacultyId = (req.body.facultyId || '').trim();
  const password = (req.body.password || '').trim();

  if (!name && !newFacultyId && !password) {
    return renderFacultyDashboard(req, res, {
      profileError: 'Provide at least one field to update.',
      profileSuccess: null,
    });
  }

  const update = {};
  if (name) update.name = name;
  if (newFacultyId) update.facultyId = newFacultyId;
  if (password) {
    try {
      update.password = await bcrypt.hash(password, 10);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to hash password', err);
    }
  }

  try {
    const updated = await Faculty.findOneAndUpdate(
      { facultyId: current.facultyId },
      { $set: update },
      { new: true },
    ).lean();

    if (!updated) {
      return res.status(404).render('staffLogin', {
        error: 'Profile not found. Please log in again.',
      });
    }

    req.session.user.name = updated.name;
    req.session.user.facultyId = updated.facultyId;

    return renderFacultyDashboard(req, res, {
      profileError: null,
      profileSuccess: 'Profile updated successfully.',
    });
  } catch (err) {
    if (err?.code === 11000) {
      return renderFacultyDashboard(req, res, {
        profileError: 'Faculty ID already exists. Choose another.',
        profileSuccess: null,
      });
    }
    // eslint-disable-next-line no-console
    console.error('Failed to update faculty profile', err);
    return renderFacultyDashboard(req, res, {
      profileError: 'Could not update profile right now. Please try again.',
      profileSuccess: null,
    });
  }
});

app.get('/hod/profile', ensureRole('hod'), async (req, res) =>
  renderHodDashboard(req, res, { initialPanel: 'profile' }),
);

app.post('/hod/profile', ensureRole('hod'), async (req, res) => {
  const current = await loadCurrentFaculty(req);
  if (!current) {
    return res.status(404).render('staffLogin', {
      error: 'Profile not found. Please log in again.',
    });
  }

  const name = (req.body.name || '').trim();
  const newFacultyId = (req.body.facultyId || '').trim();
  const password = (req.body.password || '').trim();

  if (!name && !newFacultyId && !password) {
    return renderHodDashboard(req, res, {
      profileError: 'Provide at least one field to update.',
      profileSuccess: null,
      initialPanel: 'profile',
    });
  }

  const update = {};
  if (name) update.name = name;
  if (newFacultyId) update.facultyId = newFacultyId;
  if (password) {
    try {
      update.password = await bcrypt.hash(password, 10);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to hash password', err);
    }
  }

  try {
    const updated = await Faculty.findOneAndUpdate(
      { facultyId: current.facultyId },
      { $set: update },
      { new: true },
    ).lean();

    if (!updated) {
      return res.status(404).render('staffLogin', {
        error: 'Profile not found. Please log in again.',
      });
    }

    req.session.user.name = updated.name;
    req.session.user.facultyId = updated.facultyId;

    return renderHodDashboard(req, res, {
      profileError: null,
      profileSuccess: 'Profile updated successfully.',
      initialPanel: 'profile',
    });
  } catch (err) {
    if (err?.code === 11000) {
      return renderHodDashboard(req, res, {
        profileError: 'Faculty ID already exists. Choose another.',
        profileSuccess: null,
        initialPanel: 'profile',
      });
    }
    // eslint-disable-next-line no-console
    console.error('Failed to update HOD profile', err);
    return renderHodDashboard(req, res, {
      profileError: 'Could not update profile right now. Please try again.',
      profileSuccess: null,
      initialPanel: 'profile',
    });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/student', ensureRole('student'), async (req, res) => {
  const { name } = req.session.user;
  let myRequests = [];
  try {
    myRequests = await Request.find({ studentName: name })
      .sort({ createdAt: -1 })
      .lean();
    myRequests = myRequests.map((r) => ({ ...r, id: r._id.toString() }));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load student requests', err);
  }
  // try to load any HOD final-approval for this student (by rollNumber or name)
  let hodApproval = null;
  try {
    const roll = (req.session.user && req.session.user.rollNumber) ? (req.session.user.rollNumber || '').trim() : '';
    if (roll) {
      hodApproval = await HODApproval.findOne({ rollNumber: roll }).lean();
    }
    if (!hodApproval) {
      hodApproval = await HODApproval.findOne({ studentName: name }).lean();
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load HOD approval for student', err);
  }

  res.render('studentDashboard', { requests: myRequests, hodApproval });
});

app.post('/student/requests', ensureRole('student'), async (req, res) => {
  const { department, reason } = req.body;
  const { name } = req.session.user;
  if (!department || !reason) {
    let myRequests = [];
    try {
      myRequests = await Request.find({ studentName: name })
        .sort({ createdAt: -1 })
        .lean();
      myRequests = myRequests.map((r) => ({ ...r, id: r._id.toString() }));
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to load student requests', err);
    }
    return res.status(400).render('studentDashboard', {
      requests: myRequests,
      error: 'Department and reason are required.',
    });
  }

  try {
    await Request.create({
      rollNumber: '',
      studentName: name,
      department,
      reason,
      status: 'Pending Faculty',
      facultyNote: '',
      adminNote: '',
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to create student request', err);
  }

  return res.redirect('/student');
});

app.get('/faculty', ensureRole('faculty', 'hod'), async (req, res) => renderFacultyDashboard(req, res));

// Subject assignment toggles per student: two assignments per subject
// NOTE: this route must be defined BEFORE the generic :action route below
app.post('/faculty/requests/:id/assignments', ensureRole('faculty', 'hod'), async (req, res) => {
  const { id } = req.params;
  let request;
  try {
    request = await Request.findById(id);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load request for assignments', err);
  }
  if (!request) return res.status(404).send('Request not found');

  // interpret checkbox values
  const assignment1 = !!req.body.assignment1;
  const assignment2 = !!req.body.assignment2;

  request.assignment1 = assignment1;
  request.assignment2 = assignment2;
  request.facultyNote = (req.body.facultyNote || '').trim();

  if (assignment1 && assignment2) {
    request.status = 'Approved';
    if (!request.facultyNote) request.facultyNote = 'Assignments 1 & 2 cleared';
  } else if (!assignment1 && !assignment2) {
    request.status = 'Pending Faculty';
  } else {
    request.status = 'Partially Cleared';
  }

  try {
    await request.save();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update assignment status', err);
  }
  const isHodUser = req.session?.user?.role === 'hod';
  if (isHodUser) {
    return res.redirect('/hod#hod-subject-data');
  }

  // After saving, return the user to the most relevant faculty panel.
  // Subject-based requests go to subject-wise approvals; mentor/general
  // requests (no subjectCode) go to the mentees panel.
  if (!request.subjectCode) {
    return res.redirect('/faculty#mentee-data');
  }
  return res.redirect('/faculty#student-data');
});

// Bulk update assignments and remarks for many students at once
app.post('/faculty/requests/bulk-assignments', ensureRole('faculty', 'hod'), async (req, res) => {
  const { assignments } = req.body;
  const subjectCode = (req.body.subjectCode || '').trim();
  const isHodUser = req.session?.user?.role === 'hod';
  const basePath = isHodUser ? '/hod' : '/faculty';
  const panel = isHodUser ? 'hod-subject-data' : 'student-data';

  const studentDataRedirect = subjectCode
    ? `${basePath}?subject=${encodeURIComponent(subjectCode)}#${panel}`
    : `${basePath}#${panel}`;

  if (!assignments || typeof assignments !== 'object') {
    return res.redirect(studentDataRedirect);
  }

  try {
    const ops = [];
    Object.entries(assignments).forEach(([id, data]) => {
      if (!data) return;
      const assignment1 = !!data.assignment1;
      const assignment2 = !!data.assignment2;
      let facultyNote = (data.facultyNote || '').trim();

      const update = {
        assignment1,
        assignment2,
        facultyNote,
      };

      if (assignment1 && assignment2) {
        update.status = 'Approved';
        if (!facultyNote) update.facultyNote = 'Assignments 1 & 2 cleared';
      } else if (!assignment1 && !assignment2) {
        update.status = 'Pending Faculty';
      } else {
        update.status = 'Partially Cleared';
      }

      ops.push({
        updateOne: {
          filter: { _id: id },
          update: { $set: update },
        },
      });
    });

    if (ops.length) {
      await Request.bulkWrite(ops);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to bulk update assignments', err);
  }

  return res.redirect(studentDataRedirect);
});

// Autosave endpoint for Faculty status updates (no page reload).
app.post('/faculty/requests/:id/autosave-status', ensureRole('faculty', 'hod'), async (req, res) => {
  const { id } = req.params;
  const normalizedAction = (req.body?.action || '').toString().trim();

  let request;
  try {
    request = await Request.findById(id);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load request for faculty autosave action', err);
  }
  if (!request) return res.status(404).json({ ok: false, error: 'Request not found' });

  const mentorRequest = isMentorRequest(request);
  const objectiveRequest = isObjectiveRequest(request);

  if (normalizedAction === 'approve') {
    request.status = 'Approved';
    request.facultyNote = 'Approved by faculty';
    if (mentorRequest) {
      request.assignment1 = true;
      request.assignment2 = true;
    } else if (objectiveRequest) {
      request.assignment1 = true;
      request.assignment2 = false;
    }
  } else if (normalizedAction === 'deny') {
    request.status = 'Rejected by Faculty';
    request.facultyNote = 'Denied by faculty';
    if (mentorRequest || objectiveRequest) {
      request.assignment1 = false;
      request.assignment2 = false;
    }
  } else if (normalizedAction === 'pending') {
    request.status = 'Pending Faculty';
    request.facultyNote = '';
    if (mentorRequest || objectiveRequest) {
      request.assignment1 = false;
      request.assignment2 = false;
    }
  } else {
    return res.status(400).json({ ok: false, error: 'Invalid action' });
  }

  try {
    await request.save();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to autosave faculty request status', err);
    return res.status(500).json({ ok: false, error: 'Save failed' });
  }

  return res.json({ ok: true, id: request._id.toString(), status: request.status });
});

// Legacy approve/deny for non-subject requests (still supported)
app.post('/faculty/requests/:id/:action', ensureRole('faculty', 'hod'), async (req, res) => {
  const { id, action } = req.params;
  const { note, redirectPanel, focusRequest } = req.body;
  const isHodUser = req.session?.user?.role === 'hod';
  const dashboardBase = isHodUser ? '/hod' : '/faculty';
  const allowedPanels = new Set([
    'pending',
    'student-data',
    'mentor-subject-data',
    'mentee-data',
    'objective-data',
    'profile',
    'hod-subject-data',
    'hod-mentee-data',
  ]);
  const targetPanel = allowedPanels.has(redirectPanel) ? redirectPanel : null;
  let request;
  try {
    request = await Request.findById(id);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load request for faculty action', err);
  }
  if (!request) return res.status(404).send('Request not found');

  const mentorRequest = isMentorRequest(request);
  const objectiveRequest = isObjectiveRequest(request);

  if (action === 'approve') {
    request.status = 'Approved';
    request.facultyNote = note || 'Approved by faculty';
    if (mentorRequest) {
      request.assignment1 = true;
      request.assignment2 = true;
    } else if (objectiveRequest) {
      request.assignment1 = true;
      request.assignment2 = false;
    }
  } else if (action === 'deny') {
    request.status = 'Rejected by Faculty';
    request.facultyNote = note || 'Denied by faculty';
    if (mentorRequest) {
      request.assignment1 = false;
      request.assignment2 = false;
    } else if (objectiveRequest) {
      request.assignment1 = false;
      request.assignment2 = false;
    }
  } else {
    return res.status(400).send('Invalid action');
  }

  try {
    await request.save();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update faculty request status', err);
  }

  const safeFocus = (focusRequest || '').toString().trim();
  const query = safeFocus ? `?focusRequest=${encodeURIComponent(safeFocus)}` : '';
  return res.redirect(targetPanel ? `${dashboardBase}${query}#${targetPanel}` : `${dashboardBase}${query}`);
});

app.post('/faculty/requests/approve-all', ensureRole('faculty', 'hod'), async (req, res) => {
  const scope = (req.body.scope || '').trim();
  const redirectPanel = (req.body.redirectPanel || '').trim();
  const objectiveCode = (req.body.objectiveCode || '').trim();
  const allowedPanels = new Set(['mentor-subject-data', 'objective-data', 'mentee-data', 'student-data', 'hod-subject-data']);
  const targetPanel = allowedPanels.has(redirectPanel) ? redirectPanel : 'pending';
  const subjectCode = (req.body.subjectCode || '').trim();
  const bulkAction = (req.body.bulkAction || 'approve').trim();
  const isHodUser = req.session?.user?.role === 'hod';
  const dashboardBase = isHodUser ? '/hod' : '/faculty';

  const self = await loadCurrentFaculty(req);
  if (!self || !self.facultyId) {
    return res.redirect(`/faculty#${targetPanel}`);
  }

  const baseFilter = {
    facultyId: self.facultyId,
    status: 'Pending Faculty',
  };

  try {
    if (scope === 'mentor') {
      await Request.updateMany(
        {
          ...baseFilter,
          subjectCode: { $regex: '^MENTOR::' },
        },
        {
          $set: {
            status: 'Approved',
            facultyNote: 'Approved by faculty (bulk)',
            assignment1: true,
            assignment2: true,
          },
        },
      );
    } else if (scope === 'objective') {
      const filter = {
        ...baseFilter,
        subjectCode: { $regex: '^OBJECTIVE::' },
      };
      if (objectiveCode) {
        filter.subjectCode = objectiveCode;
      }

      await Request.updateMany(
        filter,
        {
          $set: {
            status: 'Approved',
            facultyNote: 'Approved by faculty (bulk)',
            assignment1: true,
            assignment2: false,
          },
        },
      );
    } else if (scope === 'subject' && subjectCode) {
      const filter = {
        ...baseFilter,
        subjectCode,
      };
      if (bulkAction === 'revoke') {
        await Request.updateMany(
          filter,
          {
            $set: {
              status: 'Pending Faculty',
              facultyNote: '',
              assignment1: false,
              assignment2: false,
            },
          },
        );
      } else {
        await Request.updateMany(
          filter,
          {
            $set: {
              status: 'Approved',
              facultyNote: 'Approved by faculty (bulk)',
              assignment1: true,
              assignment2: true,
            },
          },
        );
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to bulk approve faculty requests', err);
  }

  return res.redirect(`${dashboardBase}#${targetPanel}`);
});

app.get('/hod', ensureRole('hod'), async (req, res) => renderHodDashboard(req, res));

// API: list requests that were force-approved by HOD (adminNote contains marker)
app.get('/api/hod/force-approved', ensureRole('hod'), async (req, res) => {
  try {
    const rows = await Request.find({
      $or: [
        { adminNote: /Force-approved by HOD/i },
        { adminNote: /Cleared by HOD/i },
      ],
      status: 'Approved',
    }).sort({ updatedAt: -1 }).lean();
    const results = rows.map((r) => ({
      id: r._id.toString(),
      rollNumber: r.rollNumber,
      studentName: r.studentName,
      department: r.department || r.branch || 'Unassigned',
      year: r.year || 'No Year',
      section: r.section || 'No Section',
      subjectCode: r.subjectCode || 'General',
      subjectName: r.subjectName || r.reason || 'General',
      facultyId: r.facultyId || null,
      status: r.status,
      approvedAt: r.updatedAt || r.createdAt,
    }));

    const deptMap = new Map();
    results.forEach((row) => {
      const dept = (row.department || 'Unassigned').toString().trim();
      const year = (row.year || 'No Year').toString().trim();
      const section = (row.section || 'No Section').toString().trim();
      const studentKey = `${row.rollNumber || ''}::${(row.studentName || '').toLowerCase()}`;

      if (!deptMap.has(dept)) deptMap.set(dept, new Map());
      const yearMap = deptMap.get(dept);
      if (!yearMap.has(year)) yearMap.set(year, new Map());
      const sectionMap = yearMap.get(year);
      if (!sectionMap.has(section)) sectionMap.set(section, new Map());
      const studentMap = sectionMap.get(section);

      if (!studentMap.has(studentKey)) {
        studentMap.set(studentKey, {
          rollNumber: row.rollNumber || '',
          studentName: row.studentName || '-',
          subjects: [],
        });
      }

      studentMap.get(studentKey).subjects.push({
        subjectName: row.subjectName || 'General',
        subjectCode: row.subjectCode || 'General',
      });
    });

    const groups = Array.from(deptMap.entries()).map(([department, yearMap]) => ({
      department,
      years: Array.from(yearMap.entries()).map(([year, sectionMap]) => ({
        year,
        sections: Array.from(sectionMap.entries()).map(([section, studentMap]) => ({
          section,
          students: Array.from(studentMap.values()).map((student) => ({
            rollNumber: student.rollNumber,
            studentName: student.studentName,
            subjects: student.subjects,
          })),
        })),
      })),
    }));

    return res.json({ items: results, groups });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to fetch force-approved requests', err);
    return res.status(500).json({ error: 'Failed to load data' });
  }
});

// Fetch pending approvals for a specific student
app.get('/api/hod/student/:rollNumber/pending-approvals', ensureRole('hod'), async (req, res) => {
  const { rollNumber } = req.params;
  if (!rollNumber) {
    return res.status(400).json({ error: 'Roll number required' });
  }

  try {
    const normalizedRoll = rollNumber.toString().trim().toUpperCase();
    const student = await Student.findOne({ rollNumber: { $regex: `^${escapeRegex(normalizedRoll)}$`, $options: 'i' } }).lean();
    
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const allRequests = await Request.find({ rollNumber: student.rollNumber }).lean();
    
    // Filter pending requests (include mentor and objective requests as requested)
    const pendingRequests = allRequests.filter((r) => r.status !== 'Approved');

    // Group by faculty and subject
    const groupedByFaculty = new Map();
    pendingRequests.forEach((req) => {
      const facultyId = req.facultyId || 'unassigned';
      if (!groupedByFaculty.has(facultyId)) {
        groupedByFaculty.set(facultyId, []);
      }
      groupedByFaculty.get(facultyId).push(req);
    });

    // Get faculty names
    const facultyIds = Array.from(groupedByFaculty.keys()).filter((id) => id !== 'unassigned');
    const faculties = facultyIds.length > 0 ? await Faculty.find({ facultyId: { $in: facultyIds } }).lean() : [];
    const facultyMap = new Map(faculties.map((f) => [f.facultyId, f.name]));

    const result = {
      student: {
        rollNumber: student.rollNumber,
        name: student.name,
        department: student.department || student.branch,
        year: student.year,
        section: student.section,
      },
      pendingApprovals: Array.from(groupedByFaculty.entries()).map(([facultyId, reqs]) => ({
        facultyId,
        facultyName: facultyMap.get(facultyId) || 'Unassigned',
        requests: reqs.map((r) => ({
          id: r._id.toString(),
          subjectCode: r.subjectCode || 'General',
          subjectName: r.subjectName || 'General Request',
          status: r.status,
          reason: r.reason,
          facultyNote: r.facultyNote,
        })),
      })),
    };

    // compute overall approval status similar to buildStudentsByDepartmentYearSection
    const nonMentorNonObjective = allRequests.filter((r) => !isMentorRequest(r) && !isObjectiveRequest(r));
    const mentorReqs = allRequests.filter((r) => isMentorRequest(r));
    const objectiveReqs = allRequests.filter((r) => isObjectiveRequest(r));
    const allApproved = (arr) => arr.length === 0 || arr.every((r) => r.status === 'Approved');
    const statuses = [];
    if (nonMentorNonObjective.length > 0) statuses.push(allApproved(nonMentorNonObjective) ? 'approved' : 'pending');
    if (mentorReqs.length > 0) statuses.push(allApproved(mentorReqs) ? 'approved' : 'pending');
    if (objectiveReqs.length > 0) statuses.push(allApproved(objectiveReqs) ? 'approved' : 'pending');
    let overallStatus = 'No Requests';
    if (statuses.length === 0) overallStatus = 'No Requests';
    else if (statuses.every((s) => s === 'approved')) overallStatus = 'Approved';
    else overallStatus = 'Pending';

    // include any existing HOD approval record
    let hodApprovalRecord = null;
    try {
      hodApprovalRecord = await HODApproval.findOne({ rollNumber: student.rollNumber }).lean();
      if (!hodApprovalRecord) {
        hodApprovalRecord = await HODApproval.findOne({ studentName: student.name }).lean();
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to load HOD approval record', err);
    }

    result.overallStatus = overallStatus;
    result.hodApproval = hodApprovalRecord || null;

    return res.json(result);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to fetch student pending approvals', err);
    return res.status(500).json({ error: 'Failed to fetch student approvals' });
  }
});

// HOD force-approve specific requests for a student
app.post('/hod/requests/force-approve', ensureRole('hod'), async (req, res) => {
  const requestIds = Array.isArray(req.body?.requestIds) ? req.body.requestIds : [];
  const redirectPanel = (req.body?.redirectPanel || 'student-list-by-department').toString().trim();

  if (!requestIds.length) {
    return res.status(400).json({ error: 'No requests selected' });
  }

  try {
    const objectIds = requestIds.map((id) => {
      try {
        return new (mongoose.mongo || mongoose.Types).ObjectId(id);
      } catch (e) {
        return null;
      }
    }).filter(Boolean);

    if (objectIds.length === 0) {
      return res.status(400).json({ error: 'Invalid request IDs' });
    }

    const result = await Request.updateMany(
      { _id: { $in: objectIds } },
      {
        $set: {
          status: 'Approved',
          assignment1: true,
          assignment2: true,
          adminNote: 'Force-approved by HOD',
        },
      }
    );

    return res.json({
      success: true,
      message: `${result.modifiedCount} request(s) approved`,
      redirectUrl: `/hod#${redirectPanel}`,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to force-approve requests', err);
    return res.status(500).json({ error: 'Failed to approve requests' });
  }
});

app.get('/hod/background-tasks/status', ensureRole('hod'), (req, res) => {
  return res.json({
    tasks: getBackgroundTaskSummaries(),
    timestamp: Date.now(),
  });
});

// Autosave endpoint for HOD mentee request status updates (no page reload).
app.post('/hod/requests/:id/autosave-status', ensureRole('hod'), async (req, res) => {
  const { id } = req.params;
  const normalizedAction = (req.body?.action || '').toString().trim();

  const self = await loadCurrentFaculty(req);
  let request;
  try {
    request = await Request.findById(id);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load request for HOD autosave action', err);
  }

  if (!request) {
    return res.status(404).json({ ok: false, error: 'Request not found' });
  }

  const mentorRequest = isMentorRequest(request);
  const ownedByHod = self && request.facultyId === self.facultyId;
  const mentorAllowed = mentorRequest && ownedByHod;
  const legacyAllowed = !mentorRequest;
  if (!mentorAllowed && !legacyAllowed) {
    return res.status(403).json({ ok: false, error: 'Request not editable' });
  }

  if (normalizedAction === 'approve') {
    request.status = 'Approved';
    request.adminNote = 'Cleared by HOD';
    if (mentorRequest) {
      request.assignment1 = true;
      request.assignment2 = true;
    }
  } else if (normalizedAction === 'deny') {
    request.status = 'Rejected by HOD';
    request.adminNote = 'Denied by HOD';
    if (mentorRequest) {
      request.assignment1 = false;
      request.assignment2 = false;
    }
  } else if (normalizedAction === 'pending') {
    request.status = 'Pending HOD';
    request.adminNote = 'Reopened for HOD review';
    if (mentorRequest) {
      request.assignment1 = false;
      request.assignment2 = false;
    }
  } else {
    return res.status(400).json({ ok: false, error: 'Invalid action' });
  }

  try {
    await request.save();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to autosave HOD request status', err);
    return res.status(500).json({ ok: false, error: 'Save failed' });
  }

  return res.json({ ok: true, id: request._id.toString(), status: request.status });
});

app.post('/hod/requests/:id/:action', ensureRole('hod'), async (req, res) => {
  const { id, action } = req.params;
  const { note, redirectPanel } = req.body;
  const allowedPanels = new Set(['hod-subject-data', 'hod-mentee-data']);
  const targetPanel = allowedPanels.has(redirectPanel) ? redirectPanel : null;
  const self = await loadCurrentFaculty(req);
  let request;
  try {
    request = await Request.findById(id);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load request for HOD action', err);
  }
  if (!request) return res.status(404).send('Request not found');
  const mentorRequest = isMentorRequest(request);
  const ownedByHod = self && request.facultyId === self.facultyId;
  const mentorAllowed = mentorRequest && ownedByHod;
  const legacyAllowed = !mentorRequest;
  if (!mentorAllowed && !legacyAllowed) {
    return res.status(403).send('Request not editable');
  }

  if (action === 'approve') {
    request.status = 'Approved';
    request.adminNote = note || 'Cleared by HOD';
    if (mentorRequest) {
      request.assignment1 = true;
      request.assignment2 = true;
    }
  } else if (action === 'deny') {
    request.status = 'Rejected by HOD';
    request.adminNote = note || 'Denied by HOD';
    if (mentorRequest) {
      request.assignment1 = false;
      request.assignment2 = false;
    }
  } else {
    return res.status(400).send('Invalid action');
  }

  try {
    await request.save();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update HOD request status', err);
  }

  const fallbackPanel = redirectToHodPanel(req, 'hod-subject-data').split('#')[1] || 'hod-subject-data';
  const panel = targetPanel || fallbackPanel;
  return res.redirect(`/hod#${panel}`);
});

app.post('/hod/requests/approve-all-mentee', ensureRole('hod'), async (req, res) => {
  const self = await loadCurrentFaculty(req);
  if (!self || !self.facultyId) {
    return res.redirect(redirectToHodPanel(req, 'hod-mentee-data'));
  }

  try {
    await Request.updateMany(
      {
        facultyId: self.facultyId,
        subjectCode: { $regex: '^MENTOR::' },
        status: { $in: ['Pending Faculty', 'Pending HOD'] },
      },
      {
        $set: {
          status: 'Approved',
          adminNote: 'Cleared by HOD (bulk)',
          assignment1: true,
          assignment2: true,
        },
      },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to bulk approve HOD mentee requests', err);
  }

  return res.redirect(redirectToHodPanel(req, 'hod-mentee-data'));
});

// HOD maintenance: remove all approval requests from the database.
app.post('/hod/requests/delete-all', ensureRole('hod'), async (req, res) => {
  try {
    await Request.deleteMany({});
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete all requests', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
});

// HOD maintenance: reset all requests back to default pending state and ensure missing requests exist.
app.post('/hod/requests/reset-all-default', ensureRole('hod'), async (req, res) => {
  runBackgroundTask('hod-reset-all-default', async (task) => {
    task.setProcessed(0);
    await Request.updateMany(
      {},
      {
        $set: {
          status: 'Pending Faculty',
          assignment1: false,
          assignment2: false,
          facultyNote: '',
          adminNote: '',
        },
      },
    );
    task.incrementProcessed(1);

    const subjects = await Subject.find().lean();
    const mentorFacultyIds = await Student.distinct('mentorFacultyId', {
      mentorFacultyId: { $nin: [null, ''] },
    });
    task.setTotal(1 + subjects.length + mentorFacultyIds.length + 1);

    for (const subject of subjects) {
      // eslint-disable-next-line no-await-in-loop
      await ensureRequestsForSubject(subject);
      // eslint-disable-next-line no-await-in-loop
      await syncSubjectRequestsFaculty(subject);
      task.incrementProcessed(1);
    }

    for (const facultyId of mentorFacultyIds) {
      // eslint-disable-next-line no-await-in-loop
      await ensureMentorRequestsForFaculty(facultyId);
      task.incrementProcessed(1);
    }

    await ensureObjectiveRequestsForAllStudents();
    task.incrementProcessed(1);
  });

  return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
});

// HOD maintenance: create missing subject requests for all students.
app.post('/hod/requests/generate-all', ensureRole('hod'), async (req, res) => {
  runBackgroundTask('hod-generate-all-requests', async (task) => {
    task.setProcessed(0);
    const subjects = await Subject.find().lean();
    task.setTotal(subjects.length + 1);
    for (const subject of subjects) {
      // eslint-disable-next-line no-await-in-loop
      await ensureRequestsForSubject(subject);
      // eslint-disable-next-line no-await-in-loop
      await syncSubjectRequestsFaculty(subject);
      task.incrementProcessed(1);
    }
    await ensureObjectiveRequestsForAllStudents();
    task.incrementProcessed(1);
  });

  return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
});

// HOD maintenance: create mentor-subject requests for all students mapped to mentors.
app.post('/hod/requests/generate-mentor-subjects', ensureRole('hod'), async (req, res) => {
  runBackgroundTask('hod-generate-mentor-subjects', async (task) => {
    task.setProcessed(0);
    const mentorFacultyIds = await Student.distinct('mentorFacultyId', {
      mentorFacultyId: { $nin: [null, ''] },
    });
    task.setTotal(mentorFacultyIds.length || 0);

    for (const facultyId of mentorFacultyIds) {
      // eslint-disable-next-line no-await-in-loop
      await ensureMentorRequestsForFaculty(facultyId);
      task.incrementProcessed(1);
    }
  });

  return res.redirect(redirectToHodPanel(req, 'hod-mentee-data'));
});

app.post('/hod/requests/delete-mentor-subjects', ensureRole('hod'), async (req, res) => {
  try {
    await Request.deleteMany({
      $or: [
        { subjectCode: { $regex: '^MENTOR::' } },
        { reason: { $regex: '^Mentor objective:' } },
        { reason: 'Mentor objectives: Achievements & Mentoring feedback' },
      ],
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete mentor requests', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
});

// HOD maintenance: create missing objective-approval requests for all applicable students.
app.post('/hod/requests/generate-objective-approvals', ensureRole('hod'), async (req, res) => {
  runBackgroundTask('hod-generate-objective-approvals', async (task) => {
    task.setTotal(1);
    task.setProcessed(0);
    await ensureObjectiveRequestsForAllStudents();
    task.incrementProcessed(1);
  });
  return res.redirect(redirectToHodPanel(req, 'manage-objective-approvals'));
});

app.post('/hod/requests/delete-objective-approvals', ensureRole('hod'), async (req, res) => {
  try {
    await Request.deleteMany({
      $or: [
        { subjectCode: { $regex: '^OBJECTIVE::' } },
        { reason: { $regex: '^Objective approval:' } },
      ],
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete objective requests', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-objective-approvals'));
});

// Manage objective approvals (e.g., NASSCOM) and assign one faculty per objective.
app.post('/hod/objective-approvals', ensureRole('hod'), async (req, res) => {
  const rawName = (req.body.name || '').trim();
  const facultyId = (req.body.facultyId || '').trim();
  const yearsRaw = req.body.years;

  if (!rawName || !facultyId) {
    return res.redirect(redirectToHodPanel(req, 'manage-objective-approvals'));
  }

  const years = Array.isArray(yearsRaw)
    ? yearsRaw.map((y) => (y || '').trim()).filter(Boolean)
    : ((yearsRaw || '').trim() ? [(yearsRaw || '').trim()] : []);

  let code = rawName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  if (!code) code = `obj-${Date.now()}`;

  try {
    // Avoid duplicate-key collisions by suffixing when needed.
    let candidate = code;
    let suffix = 2;
    // eslint-disable-next-line no-await-in-loop
    while (await ObjectiveApproval.findOne({ code: candidate }).lean()) {
      candidate = `${code}-${suffix}`;
      suffix += 1;
    }

    const objective = await ObjectiveApproval.findOneAndUpdate(
      { code: candidate },
      {
        code: candidate,
        name: rawName,
        facultyId,
        years,
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );

    await ensureObjectiveRequestsForObjective(objective);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to create objective approval', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-objective-approvals'));
});

app.post('/hod/objective-approvals/:id/delete', ensureRole('hod'), async (req, res) => {
  const { id } = req.params;
  try {
    const objective = await ObjectiveApproval.findById(id).lean();
    if (objective && objective.code) {
      await Request.deleteMany({ subjectCode: `OBJECTIVE::${objective.code}` });
    }
    await ObjectiveApproval.deleteOne({ _id: id });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete objective approval', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-objective-approvals'));
});

// Update objective approval (change name, assigned faculty, years)
app.post('/hod/objective-approvals/:id/update', ensureRole('hod'), async (req, res) => {
  const { id } = req.params;
  const rawName = (req.body.name || '').trim();
  const facultyId = (req.body.facultyId || '').trim();
  const yearsRaw = req.body.years;
  const years = Array.isArray(yearsRaw)
    ? yearsRaw.map((y) => (y || '').trim()).filter(Boolean)
    : ((yearsRaw || '').trim() ? [(yearsRaw || '').trim()] : []);

  if (!rawName) return res.redirect(redirectToHodPanel(req, 'manage-objective-approvals'));

  try {
    const updateDoc = { name: rawName };
    if (facultyId) updateDoc.facultyId = facultyId;
    if (Array.isArray(years) && years.length) updateDoc.years = years;

    const updated = await ObjectiveApproval.findByIdAndUpdate(id, updateDoc, { new: true }).lean();
    if (updated && updated.code) {
      // sync request subjectName and optionally facultyId
      const setDoc = { subjectName: rawName };
      if (facultyId) setDoc.facultyId = facultyId;
      await Request.updateMany({ subjectCode: `OBJECTIVE::${updated.code}` }, { $set: setDoc });
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update objective approval', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-objective-approvals'));
});

app.post('/hod/students', ensureRole('hod'), async (req, res) => {
  const {
    rollNumber,
    name,
    branch,
    department,
    year,
    semester,
    section,
    mentorFacultyId,
    mentorNotes,
  } = req.body;
  if (!rollNumber || !name) {
    return res.redirect(redirectToHodPanel(req, 'manage-students'));
  }
  try {
    const updatedStudent = await Student.findOneAndUpdate(
      { rollNumber: rollNumber.trim() },
      {
        rollNumber: rollNumber.trim(),
        name: name.trim(),
        branch: branch?.trim() || undefined,
        year,
        section,
        department,
        semester: semester?.trim() || undefined,
        mentorFacultyId: mentorFacultyId?.trim() || undefined,
        mentorNotes: mentorNotes?.trim() || undefined,
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );

    if (updatedStudent) {
      await ensureObjectiveRequestsForStudent(updatedStudent.toObject ? updatedStudent.toObject() : updatedStudent);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to upsert student', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-students'));
});

// HOD final-approve toggle for a student
app.post('/hod/students/:rollNumber/final-approve', ensureRole('hod'), async (req, res) => {
  const { rollNumber } = req.params;
  const actor = (req.session.user && req.session.user.facultyId) ? req.session.user.facultyId : 'HOD';

  try {
    const student = await Student.findOne({ rollNumber }).lean();
    const studentName = student ? student.name : '';

    let existing = await HODApproval.findOne({ rollNumber }).lean();
    if (!existing) {
      await HODApproval.create({ rollNumber, studentName, approved: true, approvedBy: actor, approvedAt: new Date() });
    } else if (!existing.approved) {
      await HODApproval.updateOne({ _id: existing._id }, { $set: { approved: true, approvedBy: actor, approvedAt: new Date() } });
    } else {
      // toggle off if already approved
      await HODApproval.updateOne({ _id: existing._id }, { $set: { approved: false, approvedBy: actor, approvedAt: new Date() } });
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to toggle HOD final approval', err);
  }

  return res.redirect(redirectToHodPanel(req, 'student-list-by-department'));
});

app.post('/hod/students/import', ensureRole('hod'), upload.single('csv'), async (req, res) => {
  if (!req.file) {
    return res.redirect(redirectToHodPanel(req, 'manage-students'));
  }

  try {
    const text = req.file.buffer.toString('utf8');
    const lines = text.split(/\r?\n/).filter((l) => l.trim().length);
    if (!lines.length) {
      return res.redirect(redirectToHodPanel(req, 'manage-students'));
    }

    const header = lines[0].split(',').map((h) => h.trim().toLowerCase());
    const idx = {
      rollNumber: header.indexOf('rollnumber'),
      name: header.indexOf('name'),
      branch: header.indexOf('branch'),
      department: header.indexOf('department'),
      year: header.indexOf('year'),
      semester: header.indexOf('semester'),
      section: header.indexOf('section'),
      mentorFacultyId: header.indexOf('mentorfacultyid'),
    };

    if (idx.rollNumber === -1 || idx.name === -1) {
      return res.redirect(redirectToHodPanel(req, 'manage-students'));
    }

    const ops = [];
    for (let i = 1; i < lines.length; i += 1) {
      const raw = lines[i];
      if (!raw.trim()) continue;
      const cols = raw.split(',');
      const get = (key) => {
        const position = idx[key];
        if (position === -1 || position >= cols.length) return undefined;
        const value = cols[position].trim();
        return value || undefined;
      };

      const rollNumber = get('rollNumber');
      const name = get('name');
      if (!rollNumber || !name) continue;

      const payload = {
        rollNumber: rollNumber.trim(),
        name: name.trim(),
        branch: get('branch'),
        department: get('department'),
        year: get('year'),
        semester: get('semester'),
        section: get('section'),
        mentorFacultyId: get('mentorFacultyId'),
      };

      ops.push(
        Student.findOneAndUpdate(
          { rollNumber: payload.rollNumber },
          payload,
          { upsert: true, new: true, setDefaultsOnInsert: true },
        ),
      );
    }

    if (ops.length) {
      await Promise.all(ops);
      await ensureObjectiveRequestsForAllStudents();
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to import students from CSV', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-students'));
});

app.post('/hod/students/:roll/update', ensureRole('hod'), async (req, res) => {
  const { roll } = req.params;
  const {
    rollNumber,
    name,
    branch,
    department,
    year,
    semester,
    section,
    mentorFacultyId,
    mentorNotes,
  } = req.body;
  try {
    const newRollNumber = rollNumber?.trim() || roll;
    const newName = name?.trim();

    // CASCADE: If student name is being changed, update all their requests
    if (newName) {
      await cascadeStudentDataUpdate(roll, newName);
    }

    // CASCADE: If roll number is being changed, rename all existing requests
    if (newRollNumber && newRollNumber !== roll) {
      await Request.updateMany(
        { rollNumber: roll },
        { $set: { rollNumber: newRollNumber } },
      );
    }

    const updatedStudent = await Student.findOneAndUpdate(
      { rollNumber: roll },
      {
        rollNumber: newRollNumber,
        name: newName,
        branch: branch?.trim() || undefined,
        year,
        section,
        department,
        semester: semester?.trim() || undefined,
        mentorFacultyId: mentorFacultyId?.trim() || undefined,
        mentorNotes: mentorNotes?.trim() || undefined,
      },
      { new: true },
    );

    if (updatedStudent) {
      await ensureObjectiveRequestsForStudent(updatedStudent.toObject ? updatedStudent.toObject() : updatedStudent);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update student', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-students'));
});

app.post('/hod/students/:roll/delete', ensureRole('hod'), async (req, res) => {
  const { roll } = req.params;
  try {
    await Student.deleteOne({ rollNumber: roll });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete student', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-students'));
});

app.post('/hod/faculty', ensureRole('hod'), async (req, res) => {
  const { name, facultyId, password, department, role } = req.body;
  if (!name || !facultyId || !password || !department) {
    return res.redirect(redirectToHodPanel(req, 'manage-faculty'));
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    await Faculty.findOneAndUpdate(
      { facultyId: facultyId.trim() },
      {
        name: name.trim(),
        facultyId: facultyId.trim(),
        password: hashed,
        department: department.trim(),
        role: (role || 'faculty').trim(),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to upsert faculty', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-faculty'));
});

app.post('/hod/faculty/:facultyId/update', ensureRole('hod'), async (req, res) => {
  const { facultyId } = req.params;
  const { name, department, newFacultyId, password, role } = req.body;
  const update = {};
  if (name) update.name = name.trim();
  if (department) update.department = department.trim();
  if (newFacultyId) update.facultyId = newFacultyId.trim();
  if (role) update.role = role.trim();
  if (password) {
    try {
      update.password = await bcrypt.hash(password, 10);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to hash password', err);
    }
  }
  try {
    // CASCADE: If facultyId is being changed, update all related records first
    if (newFacultyId && newFacultyId.trim() !== facultyId) {
      const trimmedNewId = newFacultyId.trim();
      await cascadeFacultyIdUpdate(facultyId, trimmedNewId);
    }

    await Faculty.findOneAndUpdate({ facultyId }, update, { new: true });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update faculty', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-faculty'));
});

app.post('/hod/faculty/:facultyId/delete', ensureRole('hod'), async (req, res) => {
  const { facultyId } = req.params;
  try {
    await Faculty.deleteOne({ facultyId });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete faculty', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-faculty'));
});

app.post('/hod/subjects', ensureRole('hod'), async (req, res) => {
  const { subjectCode, subjectName, year, semester } = req.body;
  let { facultyIds, branches, branch } = req.body;
  if (!subjectCode || !subjectName) {
    return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
  }
  if (!Array.isArray(facultyIds) && typeof facultyIds === 'string' && facultyIds.length) {
    facultyIds = [facultyIds];
  }

  // Normalize branches input: support comma-separated values or single branch
  if (!Array.isArray(branches) && typeof branches === 'string' && branches.length) {
    branches = branches.split(',').map((b) => b.trim()).filter(Boolean);
  }
  const branchList = Array.isArray(branches)
    ? branches.filter(Boolean)
    : (branch ? [branch.trim()] : []);

  // Parse section-faculty pairs
  const sectionFaculty = [];
  if (req.body.sectionNames && req.body.sectionFacultyIds) {
    const sections = Array.isArray(req.body.sectionNames) ? req.body.sectionNames : [req.body.sectionNames];
    const faculties = Array.isArray(req.body.sectionFacultyIds) ? req.body.sectionFacultyIds : [req.body.sectionFacultyIds];
    
    sections.forEach((section, idx) => {
      const trimmedSection = (section || '').trim();
      const trimmedFacultyId = (faculties[idx] || '').trim();
      if (trimmedSection && trimmedFacultyId) {
        sectionFaculty.push({ section: trimmedSection, facultyId: trimmedFacultyId });
      }
    });
  }

  try {
    const trimmedCode = subjectCode.trim();
    const trimmedName = subjectName.trim();

    // Create or update one subject offering per branch so that
    // the same subject code can have different faculties per branch.
    const effectiveBranches = branchList.length ? branchList : [undefined];
    for (const br of effectiveBranches) {
      // eslint-disable-next-line no-await-in-loop
      const subject = await Subject.findOneAndUpdate(
        { subjectCode: trimmedCode, branch: br || undefined },
        {
          subjectCode: trimmedCode,
          subjectName: trimmedName,
          branch: br || undefined,
          branches: br ? [br] : [],
          year,
          semester,
          facultyIds: facultyIds || [],
          sectionFaculty: sectionFaculty.length ? sectionFaculty : [],
        },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      );
      // eslint-disable-next-line no-await-in-loop
      await ensureRequestsForSubject(subject);
      // eslint-disable-next-line no-await-in-loop
      await syncSubjectRequestsFaculty(subject);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to upsert subject(s)', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
});

app.post('/hod/subjects/:code/update', ensureRole('hod'), async (req, res) => {
  const { code } = req.params;
  const { subjectCode, subjectName, year, semester, originalBranch } = req.body;
  let { facultyIds, branches, branch } = req.body;
  if (!Array.isArray(facultyIds) && typeof facultyIds === 'string' && facultyIds.length) {
    facultyIds = [facultyIds];
  }
  // Normalize branches input (we use only the first branch value for this row)
  if (!Array.isArray(branches) && typeof branches === 'string' && branches.length) {
    branches = branches.split(',').map((b) => b.trim()).filter(Boolean);
  }
  const branchList = Array.isArray(branches)
    ? branches.filter(Boolean)
    : (branch ? [branch.trim()] : []);

  // Parse section-faculty pairs
  const sectionFaculty = [];
  if (req.body.sectionNames && req.body.sectionFacultyIds) {
    const sections = Array.isArray(req.body.sectionNames) ? req.body.sectionNames : [req.body.sectionNames];
    const faculties = Array.isArray(req.body.sectionFacultyIds) ? req.body.sectionFacultyIds : [req.body.sectionFacultyIds];
    
    sections.forEach((section, idx) => {
      const trimmedSection = (section || '').trim();
      const trimmedFacultyId = (faculties[idx] || '').trim();
      if (trimmedSection && trimmedFacultyId) {
        sectionFaculty.push({ section: trimmedSection, facultyId: trimmedFacultyId });
      }
    });
  }

  const newBranch = branchList[0] || undefined;
  const filter = { subjectCode: code };
  if (typeof originalBranch === 'string' && originalBranch.trim()) {
    filter.branch = originalBranch.trim();
  }

  try {
    const trimmedCode = subjectCode?.trim() || code;
    const trimmedName = subjectName?.trim();

    // CASCADE: If subject code is being changed, update all requests with old code
    if (trimmedCode && trimmedCode !== code) {
      await cascadeSubjectCodeUpdate(code, trimmedCode, filter.branch);
    }

    // CASCADE: If subject name is being changed, update all requests with new name
    if (trimmedName) {
      await cascadeSubjectNameUpdate(code, trimmedName, filter.branch);
    }

    const subject = await Subject.findOneAndUpdate(
      filter,
      {
        subjectCode: trimmedCode,
        subjectName: trimmedName,
        branch: newBranch,
        branches: newBranch ? [newBranch] : [],
        year,
        semester,
        facultyIds: facultyIds || [],
        sectionFaculty: sectionFaculty.length ? sectionFaculty : [],
      },
      { new: true },
    );
    await ensureRequestsForSubject(subject);
    await syncSubjectRequestsFaculty(subject);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update subject', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
});

app.post('/hod/mentors/assign', ensureRole('hod'), async (req, res) => {
  const { mentorFacultyId, rollNumbers, mentorNotes } = req.body;
  if (!mentorFacultyId || !rollNumbers) {
    return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
  }

  const rolls = rollNumbers
    .split(',')
    .map((r) => r.trim())
    .filter(Boolean);

  try {
    const mentorId = mentorFacultyId.trim();
    const mentorNote = mentorNotes ? mentorNotes.trim() : '';

    // Get current mentor IDs for these students to detect changes
    const currentStudents = await Student.find({ rollNumber: { $in: rolls } }).lean();
    const oldMentorMap = new Map(
      currentStudents.map((s) => [s.rollNumber, s.mentorFacultyId]),
    );

    // Update students with mentor information
    await Student.updateMany(
      { rollNumber: { $in: rolls } },
      {
        mentorFacultyId: mentorId,
        ...(mentorNote ? { mentorNotes: mentorNote } : {}),
      },
    );

    // CASCADE: Update any mentor requests with old mentor ID to new mentor ID
    const oldMentorIds = Array.from(
      new Set(
        Array.from(oldMentorMap.values()).filter(
          (id) => id && id !== mentorId,
        ),
      ),
    );
    const mentorReason = 'Mentor objectives: Achievements & Mentoring feedback';
    if (oldMentorIds.length > 0) {
      await Request.updateMany(
        {
          rollNumber: { $in: rolls },
          reason: mentorReason,
          facultyId: { $in: oldMentorIds },
        },
        { $set: { facultyId: mentorId } },
      );
    }

    // Create or update mentor no-due objectives for each mapped student.
    const students = await Student.find({ rollNumber: { $in: rolls } }).lean();
    for (const stu of students) {
      const base = {
        rollNumber: stu.rollNumber,
        studentName: stu.name,
        facultyId: mentorId,
        department: stu.department || stu.branch || '',
        branch: stu.branch || '',
        year: stu.year || '',
        semester: stu.semester || '',
        section: stu.section || '',
      };

      // Use a fixed reason so faculty dashboard can recognize mentor objectives.
      const reason = 'Mentor objectives: Achievements & Mentoring feedback';

      // eslint-disable-next-line no-await-in-loop
      await Request.findOneAndUpdate(
        {
          rollNumber: stu.rollNumber,
          subjectCode: { $in: [null, ''] },
          reason,
        },
        {
          ...base,
          subjectCode: null,
          subjectName: null,
          reason,
          status: 'Pending Faculty',
        },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      );
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to assign mentors', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
});

// Manage mentor subjects (common to all mentors)
app.post('/hod/mentor-subjects', ensureRole('hod'), async (req, res) => {
  const rawName = (req.body.name || '').trim();
  const yearsRaw = req.body.years;
  if (!rawName) {
    return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
  }

  const years = Array.isArray(yearsRaw)
    ? yearsRaw.map((y) => (y || '').trim()).filter(Boolean)
    : ((yearsRaw || '').trim() ? [(yearsRaw || '').trim()] : []);

  // Auto-generate an internal code from the name
  let code = rawName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  if (!code) {
    code = `ment-${Date.now()}`;
  }

  try {
    await MentorSubject.findOneAndUpdate(
      { code },
      { code, name: rawName, years },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to upsert mentor subject', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
});

// Update mentor subject (change name / years)
app.post('/hod/mentor-subjects/:id/update', ensureRole('hod'), async (req, res) => {
  const { id } = req.params;
  const rawName = (req.body.name || '').trim();
  const yearsRaw = req.body.years;

  if (!rawName) return res.redirect(redirectToHodPanel(req, 'manage-mentors'));

  try {
    const updateDoc = { name: rawName };
    // Preserve existing applicable years when editor submits name-only updates.
    if (typeof yearsRaw !== 'undefined') {
      const years = Array.isArray(yearsRaw)
        ? yearsRaw.map((y) => (y || '').trim()).filter(Boolean)
        : ((yearsRaw || '').trim() ? [(yearsRaw || '').trim()] : []);
      updateDoc.years = years;
    }

    const updated = await MentorSubject.findByIdAndUpdate(id, updateDoc, { new: true }).lean();
    if (updated && updated.code) {
      // keep requests in sync: update subjectName for mentor request rows
      await Request.updateMany({ subjectCode: `MENTOR::${updated.code}` }, { $set: { subjectName: rawName } });
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update mentor subject', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
});

app.post('/hod/mentor-subjects/:id/delete', ensureRole('hod'), async (req, res) => {
  const { id } = req.params;
  try {
    const mentorSubject = await MentorSubject.findById(id).lean();
    if (mentorSubject && mentorSubject.code) {
      await Request.deleteMany({ subjectCode: `MENTOR::${mentorSubject.code}` });
    }
    await MentorSubject.deleteOne({ _id: id });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete mentor subject', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
});

app.post('/hod/subjects/:code/delete', ensureRole('hod'), async (req, res) => {
  const { code } = req.params;
  const { originalBranch } = req.body;
  const filter = { subjectCode: code };
  if (typeof originalBranch === 'string' && originalBranch.trim()) {
    filter.branch = originalBranch.trim();
  }
  try {
    // Delete the subject offering itself
    await Subject.deleteOne(filter);

    // Also delete all associated Requests for this subject offering
    const requestFilter = { subjectCode: code };
    if (filter.branch) requestFilter.branch = filter.branch;
    await Request.deleteMany(requestFilter);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete subject and its requests', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
});

app.get('/admin', ensureRole('admin'), async (req, res) => {
  let allRequests = [];
  try {
    allRequests = await Request.find().sort({ createdAt: -1 }).lean();
    allRequests = allRequests.map((r) => ({ ...r, id: r._id.toString() }));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load admin requests', err);
  }

  res.render('adminDashboard', {
    pending: allRequests.filter((r) => r.status === 'Pending HOD'),
    all: allRequests,
  });
});

app.post('/admin/requests/:id/:action', ensureRole('admin'), async (req, res) => {
  const { id, action } = req.params;
  const { note } = req.body;
  let request;
  try {
    request = await Request.findById(id);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load request for admin action', err);
  }
  if (!request) return res.status(404).send('Request not found');

  if (action === 'approve') {
    request.status = 'Approved';
    request.adminNote = note || 'Cleared by admin';
  } else if (action === 'deny') {
    request.status = 'Rejected by Admin';
    request.adminNote = note || 'Denied by admin';
  } else {
    return res.status(400).send('Invalid action');
  }

  try {
    await request.save();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update admin request status', err);
  }

  return res.redirect('/admin');
});

app.use((req, res) => {
  res.status(404).render('login', {
    error: 'Page not found. Please log in again.',
    searchError: null,
    searchResult: null,
  });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`nodue server listening on http://localhost:${PORT}`);
});
