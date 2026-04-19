const express = require('express');
const path = require('path');
const session = require('express-session');
const morgan = require('morgan');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const upload = multer({ storage: multer.memoryStorage() });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('dev'));
app.use(
  session({
    secret: 'replace-this-secret',
    resave: false,
    saveUninitialized: false,
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
  return reason.startsWith('Mentor objective:') || subjectCode.startsWith('MENTOR::');
};

const isObjectiveRequest = (request) => {
  const reason = request?.reason || '';
  const subjectCode = request?.subjectCode || '';
  return reason.startsWith('Objective approval:') || subjectCode.startsWith('OBJECTIVE::');
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
  'student-clearance-search',
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

const isStudentInObjectiveYears = (studentYear, objectiveYears) => {
  if (!Array.isArray(objectiveYears) || !objectiveYears.length) return true;
  const sy = normalizeYearToken(studentYear);
  if (!sy) return false;
  const allowed = objectiveYears
    .map((y) => normalizeYearToken(y))
    .filter(Boolean);
  return allowed.includes(sy);
};

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

      if (hasMentorSubjects) {
        for (const mentorSubject of mentorSubjects) {
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
  const mentorSubjectRequests = mentorRequests.filter((r) => (r.subjectCode || '').startsWith('MENTOR::'));
  const objectiveRequests = myRequests.filter((r) => isObjectiveRequest(r));

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
    const rows = (objectiveRequestMap.get(code) || []).slice().sort((a, b) => compareRollNumbers(a.rollNumber, b.rollNumber));
    return {
      code: objective.code,
      name: objective.name,
      facultyId: objective.facultyId,
      years: objective.years || [],
      rows,
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
      rows: (objectiveRequestMap.get(key) || []).slice().sort((a, b) => compareRollNumbers(a.rollNumber, b.rollNumber)),
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
    group.rows.sort((a, b) => {
      const ra = (a.rollNumber || '').toString();
      const rb = (b.rollNumber || '').toString();
      return ra.localeCompare(rb);
    });
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
    objectiveRequests,
    objectiveApprovals,
    objectiveGroups,
    mentorSubjects,
    subjectGroups,
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
      group.rows.sort((a, b) => {
        return compareRollNumbers(a.rollNumber, b.rollNumber);
      });
    });

    hodSubjectGroups = subjectGroups.map((group) => {
      const pendingRows = group.rows.filter((r) => r.status !== 'Approved');
      return {
        ...group,
        pendingRows: pendingRows.slice().sort((a, b) => compareRollNumbers(a.rollNumber, b.rollNumber)),
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
      return (
        r.facultyId === self.facultyId &&
        isMentorRequest(r) &&
        ['Pending Faculty', 'Pending HOD'].includes(r.status)
      );
    });

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

  const payload = {
    pending: pendingRequests,
    all: allRequests,
    pendingMentorRequests,
    hodMentorRequests,
    students,
    faculties,
    subjects,
    mentorSubjects,
    objectiveApprovals,
    self,
    subjectGroups,
    hodSubjectGroups,
    pendingSubjectGroups,
    dataError,
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

app.post('/login', async (req, res) => {
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

    const faculty = await Faculty.findOne({ facultyId: staffId }).lean();
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
    const student = await Student.findOne({ rollNumber }).lean();
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
      rollNumber,
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

    const mentorSubjectCodes = mentorSubjects.map((m) => `MENTOR::${m.code}`);
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

      const objectives = mentorSubjects.map((ms) => {
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

    return res.render('login', {
      error: null,
      searchError: null,
      searchResult: {
        rollNumber,
        student,
        subjects: subjectStatuses,
        mentorInfo,
        objectiveInfo,
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
    const student = await Student.findOne({ rollNumber }).lean();
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
      rollNumber,
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

    const mentorSubjectCodes = mentorSubjects.map((m) => `MENTOR::${m.code}`);
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

      const objectives = mentorSubjects.map((ms) => {
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
  res.render('studentDashboard', { requests: myRequests });
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

// Legacy approve/deny for non-subject requests (still supported)
app.post('/faculty/requests/:id/:action', ensureRole('faculty', 'hod'), async (req, res) => {
  const { id, action } = req.params;
  const { note, redirectPanel } = req.body;
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
  if (request.status !== 'Pending Faculty') return res.status(400).send('Request already processed');

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

  return res.redirect(targetPanel ? `${dashboardBase}#${targetPanel}` : dashboardBase);
});

app.post('/faculty/requests/approve-all', ensureRole('faculty', 'hod'), async (req, res) => {
  const scope = (req.body.scope || '').trim();
  const redirectPanel = (req.body.redirectPanel || '').trim();
  const objectiveCode = (req.body.objectiveCode || '').trim();
  const allowedPanels = new Set(['mentor-subject-data', 'objective-data', 'mentee-data']);
  const targetPanel = allowedPanels.has(redirectPanel) ? redirectPanel : 'pending';

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
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to bulk approve faculty requests', err);
  }

  return res.redirect(`/faculty#${targetPanel}`);
});

app.get('/hod', ensureRole('hod'), async (req, res) => renderHodDashboard(req, res));

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
  const mentorAllowed = mentorRequest && ownedByHod && ['Pending Faculty', 'Pending HOD'].includes(request.status);
  const legacyAllowed = !mentorRequest && request.status === 'Pending HOD';
  if (!mentorAllowed && !legacyAllowed) {
    return res.status(400).send('Request already processed');
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

  return res.redirect(targetPanel ? `/hod#${targetPanel}` : redirectToHodPanel(req, 'hod-subject-data'));
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

// HOD maintenance: create missing subject requests for all students.
app.post('/hod/requests/generate-all', ensureRole('hod'), async (req, res) => {
  try {
    const subjects = await Subject.find().lean();
    for (const subject of subjects) {
      // eslint-disable-next-line no-await-in-loop
      await ensureRequestsForSubject(subject);
      // eslint-disable-next-line no-await-in-loop
      await syncSubjectRequestsFaculty(subject);
    }
    await ensureObjectiveRequestsForAllStudents();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to generate requests for all subjects', err);
  }

  return res.redirect(redirectToHodPanel(req, 'manage-subjects'));
});

// HOD maintenance: create mentor-subject requests for all students mapped to mentors.
app.post('/hod/requests/generate-mentor-subjects', ensureRole('hod'), async (req, res) => {
  try {
    const mentorFacultyIds = await Student.distinct('mentorFacultyId', {
      mentorFacultyId: { $nin: [null, ''] },
    });

    for (const facultyId of mentorFacultyIds) {
      // eslint-disable-next-line no-await-in-loop
      await ensureMentorRequestsForFaculty(facultyId);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to generate mentor subject requests', err);
  }

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
  await ensureObjectiveRequestsForAllStudents();
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
  if (!rawName) {
    return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
  }

  // Auto-generate an internal code from the name
  let code = rawName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  if (!code) {
    code = `ment-${Date.now()}`;
  }

  try {
    await MentorSubject.findOneAndUpdate(
      { code },
      { code, name: rawName },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to upsert mentor subject', err);
  }
  return res.redirect(redirectToHodPanel(req, 'manage-mentors'));
});

app.post('/hod/mentor-subjects/:id/delete', ensureRole('hod'), async (req, res) => {
  const { id } = req.params;
  try {
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
  if (request.status !== 'Pending HOD') return res.status(400).send('Request already processed');

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
