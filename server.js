const express = require('express');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const path = require('path');
const db = require('./db');
const questions = require('./questions');

const app = express();
const PORT = process.env.PORT || 3000;

// ⚠️ ADMIN PASSWORD (change to your own secret if you want)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AKASHI';

// 🕵️ Secret student-to-admin shortcut (just for reference — real trigger is in public/index.html)
const ADMIN_TRIGGER_NAME = 'biruk';
const ADMIN_TRIGGER_CODE = 'h1t3';

const DAY_MS = 24 * 60 * 60 * 1000;
const EXAM_DURATION_MS = 20 * 60 * 1000;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const joinLimiter = rateLimit({ windowMs: 60_000, max: 10 });
const submitLimiter = rateLimit({ windowMs: 60_000, max: 5 });
const unlockLimiter = rateLimit({ windowMs: 60_000, max: 10 });

// ---- Helpers ----
function getChallengeStart() {
  return parseInt(db.prepare('SELECT value FROM config WHERE key = ?').get('challenge_start').value, 10);
}
function getChallengeEnd() { return getChallengeStart() + 3 * DAY_MS; }
function getPin() {
  return db.prepare('SELECT value FROM config WHERE key = ?').get('pin').value;
}

// ============================================================
// JOIN
// ============================================================
app.post('/api/join', joinLimiter, (req, res) => {
  try {
    const { name, code } = req.body;

    if (!name || !code) return res.status(400).json({ error: 'Name and code are required' });
    if (name.trim().length < 2) return res.status(400).json({ error: 'Please enter your full name' });
    if (code.trim().length < 3) return res.status(400).json({ error: 'Code must be at least 3 characters' });

    const cleanCode = code.trim().toUpperCase();
    const cleanName = name.trim();

    const exists = db.prepare('SELECT 1 FROM students WHERE code = ?').get(cleanCode);
    if (exists) return res.status(409).json({ error: 'This code is already taken. Choose a different one.' });

    db.prepare(`INSERT INTO students (code, name, joined_at) VALUES (?, ?, ?)`)
      .run(cleanCode, cleanName, Date.now());

    res.cookie('code', cleanCode, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 12 * 60 * 60 * 1000
    });

    res.json({ ok: true, student: { name: cleanName, code: cleanCode } });
  } catch (err) {
    console.error('Join error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// ME
// ============================================================
app.get('/api/me', (req, res) => {
  const code = req.cookies.code;
  if (!code) return res.status(401).json({ error: 'Not joined' });
  const student = db.prepare('SELECT code, name FROM students WHERE code = ?').get(code);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  res.json({ student: { name: student.name, code: student.code } });
});

// ============================================================
// LOGOUT
// ============================================================
app.post('/api/logout', (req, res) => {
  res.clearCookie('code');
  res.json({ ok: true });
});

// ============================================================
// CHALLENGE STATUS
// ============================================================
app.get('/api/status', (req, res) => {
  const start = getChallengeStart();
  const now = Date.now();
  const end = getChallengeEnd();
  res.json({
    challengeStart: start,
    challengeEnd: end,
    dayUnlocks: [start, start + DAY_MS, start + 2 * DAY_MS],
    challengeOver: now >= end,
    challengeStarted: now >= start,
    now
  });
});

// ============================================================
// START EXAM
// ============================================================
app.post('/api/start', (req, res) => {
  try {
    const code = req.cookies.code;
    if (!code) return res.status(401).json({ error: 'Not joined' });

    const now = Date.now();
    const start = getChallengeStart();
    const end = getChallengeEnd();

    if (now < start) return res.status(403).json({ error: 'Challenge has not started yet' });
    if (now >= end) return res.status(403).json({ error: 'Challenge has ended' });

    const existing = db.prepare('SELECT submitted FROM attempts WHERE code = ?').get(code);
    if (existing) return res.status(403).json({ error: 'You have already attempted this exam' });

    db.prepare(`INSERT INTO attempts (code, started_at, submitted) VALUES (?, ?, 0)`)
      .run(code, now);

    const safeQuestions = questions.map(({ correct, ...q }) => q);
    res.json({ questions: safeQuestions, examDurationMs: EXAM_DURATION_MS, startedAt: now });
  } catch (err) {
    console.error('Start error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// SUBMIT
// ============================================================
app.post('/api/submit', submitLimiter, (req, res) => {
  try {
    const code = req.cookies.code;
    if (!code) return res.status(401).json({ error: 'Not joined' });

    const { answers } = req.body;
    if (!Array.isArray(answers)) return res.status(400).json({ error: 'Invalid submission' });

    const attempt = db.prepare('SELECT * FROM attempts WHERE code = ?').get(code);
    if (!attempt) return res.status(403).json({ error: 'No active attempt' });
    if (attempt.submitted) return res.status(403).json({ error: 'Already submitted' });

    const now = Date.now();
    const elapsed = now - attempt.started_at;

    let score = 0;
    answers.forEach((ans, i) => {
      if (ans === questions[i].correct) score++;
    });

    db.prepare(`
      UPDATE attempts
      SET answers = ?, score = ?, time_taken = ?, submitted_at = ?, submitted = 1
      WHERE code = ?
    `).run(JSON.stringify(answers), score, Math.floor(elapsed / 1000), now, code);

    res.json({ score, total: questions.length, timeTaken: Math.floor(elapsed / 1000) });
  } catch (err) {
    console.error('Submit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// MY ATTEMPT
// ============================================================
app.get('/api/my-attempt', (req, res) => {
  const code = req.cookies.code;
  if (!code) return res.json({ attempt: null });

  const row = db.prepare('SELECT submitted, score, time_taken, started_at, submitted_at FROM attempts WHERE code = ?').get(code);
  if (!row) return res.json({ attempt: null });
  res.json({
    attempt: {
      submitted: !!row.submitted,
      score: row.score,
      timeTaken: row.time_taken,
      startedAt: row.started_at,
      submittedAt: row.submitted_at
    }
  });
});

// ============================================================
// WINNER (PIN required, after Day 3)
// ============================================================
app.post('/api/winner', unlockLimiter, (req, res) => {
  const now = Date.now();
  if (now < getChallengeEnd()) return res.status(403).json({ error: 'Challenge is not over yet' });

  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'PIN required' });

  if (pin.trim() !== getPin()) {
    return res.status(401).json({ error: 'Incorrect PIN' });
  }

  const winner = db.prepare(`
    SELECT s.name AS name, a.score, a.time_taken
    FROM attempts a
    JOIN students s ON s.code = a.code
    WHERE a.submitted = 1
    ORDER BY a.score DESC, a.time_taken ASC
    LIMIT 1
  `).get();

  if (!winner) return res.json({ winner: null, message: 'No submissions yet' });

  res.json({
    winner: {
      name: winner.name,
      score: winner.score,
      timeTaken: winner.time_taken,
      total: questions.length
    }
  });
});

// ============================================================
// ADMIN — Serve admin page
// ============================================================
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ============================================================
// ADMIN — Data API (password required)
// ============================================================
app.post('/api/admin/data', (req, res) => {
  const { password } = req.body;

  // Allow case-insensitive comparison + trim spaces
  if (!password || password.trim().toUpperCase() !== ADMIN_PASSWORD.toUpperCase()) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  const totalJoined = db.prepare('SELECT COUNT(*) AS n FROM students').get().n;
  const totalSubmitted = db.prepare('SELECT COUNT(*) AS n FROM attempts WHERE submitted = 1').get().n;
  const totalInProgress = db.prepare('SELECT COUNT(*) AS n FROM attempts WHERE submitted = 0').get().n;

  const students = db.prepare(`
    SELECT
      s.name, s.code, s.joined_at,
      a.score, a.submitted, a.time_taken, a.started_at
    FROM students s
    LEFT JOIN attempts a ON a.code = s.code
    ORDER BY s.joined_at ASC
  `).all();

  const leaderboard = db.prepare(`
    SELECT s.name, s.code, a.score, a.time_taken
    FROM attempts a
    JOIN students s ON s.code = a.code
    WHERE a.submitted = 1
    ORDER BY a.score DESC, a.time_taken ASC
  `).all();

  res.json({
    stats: { totalJoined, totalSubmitted, totalInProgress },
    students: students.map(s => ({
      name: s.name,
      code: s.code,
      joinedAt: s.joined_at,
      score: s.score,
      submitted: !!s.submitted,
      timeTaken: s.time_taken,
      startedAt: s.started_at
    })),
    leaderboard: leaderboard.map((s, i) => ({
      rank: i + 1,
      name: s.name,
      code: s.code,
      score: s.score,
      timeTaken: s.time_taken
    }))
  });
});

// ============================================================
// CATCH-ALL (must be LAST)
// ============================================================
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════╗');
  console.log('║   🚀 H.S.G. 3-Day Challenge Server Running          ║');
  console.log('╚═══════════════════════════════════════════════════╝');
  console.log('');
  console.log(`   👉 Open:          http://localhost:${PORT}`);
  console.log(`   🔐 Admin page:    http://localhost:${PORT}/admin`);
  console.log(`   🔑 Admin password: ${ADMIN_PASSWORD}`);
  console.log('');
});
