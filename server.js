const express = require('express');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const path = require('path');
const db = require('./db');
const questions = require('./questions');

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AKASHI';

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

function getChallengeStart() {
  return parseInt(db.prepare('SELECT value FROM config WHERE key = ?').get('challenge_start').value, 10);
}
function getChallengeEnd() { return getChallengeStart() + 3 * DAY_MS; }
function getPin() {
  return db.prepare('SELECT value FROM config WHERE key = ?').get('pin').value;
}

// ---- Which day is currently active? ----
// Day 1: from start to start+24h
// Day 2: from start+24h to start+48h
// Day 3: from start+48h to start+72h
// 0 = not started, 4 = over
function getCurrentDay() {
  const start = getChallengeStart();
  const now = Date.now();
  const diff = now - start;
  if (diff < 0) return 0;
  if (diff < DAY_MS) return 1;
  if (diff < 2 * DAY_MS) return 2;
  if (diff < 3 * DAY_MS) return 3;
  return 4;
}

// ---- Which days has the student completed? ----
function getCompletedDays(code) {
  const rows = db.prepare('SELECT day FROM attempts WHERE code = ? AND submitted = 1').all(code);
  return rows.map(r => r.day);
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

    const existingByCode = db.prepare('SELECT name, code FROM students WHERE code = ?').get(cleanCode);

    if (existingByCode) {
      if (existingByCode.name.toLowerCase() === cleanName.toLowerCase()) {
        res.cookie('code', cleanCode, {
          httpOnly: true, sameSite: 'lax', maxAge: 12 * 60 * 60 * 1000
        });
        return res.json({ ok: true, student: { name: existingByCode.name, code: existingByCode.code } });
      } else {
        return res.status(409).json({ error: 'This code is already taken. Choose a different one.' });
      }
    }

    const existingByName = db.prepare('SELECT code FROM students WHERE LOWER(name) = LOWER(?)').get(cleanName);
    if (existingByName) {
      return res.status(409).json({
        error: 'This name is already registered with code: ' + existingByName.code + '. Please use that code.'
      });
    }

    db.prepare(`INSERT INTO students (code, name, joined_at) VALUES (?, ?, ?)`)
      .run(cleanCode, cleanName, Date.now());

    res.cookie('code', cleanCode, {
      httpOnly: true, sameSite: 'lax', maxAge: 12 * 60 * 60 * 1000
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
// STATUS
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
    currentDay: getCurrentDay(),
    now
  });
});

// ============================================================
// MY PROGRESS — which days are done?
// ============================================================
app.get('/api/my-progress', (req, res) => {
  const code = req.cookies.code;
  if (!code) return res.json({ progress: [] });

  const rows = db.prepare(`
    SELECT day, score, time_taken, submitted, started_at
    FROM attempts
    WHERE code = ?
    ORDER BY day ASC
  `).all(code);

  res.json({
    progress: rows.map(r => ({
      day: r.day,
      submitted: !!r.submitted,
      score: r.score,
      timeTaken: r.time_taken,
      startedAt: r.started_at
    }))
  });
});

// ============================================================
// START EXAM — for a specific day
// ============================================================
app.post('/api/start', (req, res) => {
  try {
    const code = req.cookies.code;
    if (!code) return res.status(401).json({ error: 'Not joined' });

    const { day } = req.body;
    if (![1, 2, 3].includes(day)) return res.status(400).json({ error: 'Invalid day' });

    const now = Date.now();
    const start = getChallengeStart();
    const end = getChallengeEnd();

    if (now < start) return res.status(403).json({ error: 'Challenge has not started yet' });
    if (now >= end) return res.status(403).json({ error: 'Challenge has ended' });

    // Check if this day is unlocked yet
    const dayUnlockTime = start + (day - 1) * DAY_MS;
    if (now < dayUnlockTime) {
      return res.status(403).json({ error: `Day ${day} hasn't unlocked yet` });
    }

    // Check if student already did this day
    const existing = db.prepare('SELECT submitted FROM attempts WHERE code = ? AND day = ?').get(code, day);
    if (existing) {
      if (existing.submitted) {
        return res.status(403).json({ error: `You have already completed Day ${day}` });
      }
      // Started but not submitted — resume
      const attempt = db.prepare('SELECT started_at FROM attempts WHERE code = ? AND day = ?').get(code, day);
      const elapsed = Date.now() - attempt.started_at;
      if (elapsed > EXAM_DURATION_MS + 5000) {
        return res.status(403).json({ error: `Time for Day ${day} has expired` });
      }
      const qs = questions[`day${day}`].map(({ correct, ...q }) => q);
      return res.json({
        questions: qs,
        examDurationMs: EXAM_DURATION_MS,
        startedAt: attempt.started_at,
        day
      });
    }

    // New attempt
    db.prepare(`INSERT INTO attempts (code, day, started_at, submitted) VALUES (?, ?, ?, 0)`)
      .run(code, day, now);

    const qs = questions[`day${day}`].map(({ correct, ...q }) => q);
    res.json({ questions: qs, examDurationMs: EXAM_DURATION_MS, startedAt: now, day });
  } catch (err) {
    console.error('Start error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// SUBMIT — for a specific day
// ============================================================
app.post('/api/submit', submitLimiter, (req, res) => {
  try {
    const code = req.cookies.code;
    if (!code) return res.status(401).json({ error: 'Not joined' });

    const { day, answers } = req.body;
    if (![1, 2, 3].includes(day)) return res.status(400).json({ error: 'Invalid day' });
    if (!Array.isArray(answers)) return res.status(400).json({ error: 'Invalid submission' });

    const attempt = db.prepare('SELECT * FROM attempts WHERE code = ? AND day = ?').get(code, day);
    if (!attempt) return res.status(403).json({ error: 'No active attempt for this day' });
    if (attempt.submitted) return res.status(403).json({ error: 'Already submitted' });

    const now = Date.now();
    const elapsed = now - attempt.started_at;

    let score = 0;
    const dayQuestions = questions[`day${day}`];
    answers.forEach((ans, i) => {
      if (ans === dayQuestions[i].correct) score++;
    });

    db.prepare(`
      UPDATE attempts
      SET answers = ?, score = ?, time_taken = ?, submitted_at = ?, submitted = 1
      WHERE code = ? AND day = ?
    `).run(JSON.stringify(answers), score, Math.floor(elapsed / 1000), now, code, day);

    res.json({ day, score, total: dayQuestions.length, timeTaken: Math.floor(elapsed / 1000) });
  } catch (err) {
    console.error('Submit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// WINNER (PIN required, after Day 3)
// Based on TOTAL score across 3 days + fastest combined time
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
    SELECT
      s.name AS name,
      s.code AS code,
      SUM(a.score) AS total_score,
      SUM(a.time_taken) AS total_time,
      COUNT(a.day) AS days_done
    FROM attempts a
    JOIN students s ON s.code = a.code
    WHERE a.submitted = 1
    GROUP BY a.code
    HAVING days_done = 3
    ORDER BY total_score DESC, total_time ASC
    LIMIT 1
  `).get();

  if (!winner) {
    return res.json({ winner: null, message: 'No one has completed all 3 days yet' });
  }

  res.json({
    winner: {
      name: winner.name,
      code: winner.code,
      totalScore: winner.total_score,
      totalMax: 45, // 15 per day × 3
      totalTime: winner.total_time
    }
  });
});

// ============================================================
// ADMIN — Page
// ============================================================
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ============================================================
// ADMIN — Data API
// ============================================================
app.post('/api/admin/data', (req, res) => {
  const { password } = req.body;

  if (!password || password.trim().toUpperCase() !== ADMIN_PASSWORD.toUpperCase()) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  const totalJoined = db.prepare('SELECT COUNT(*) AS n FROM students').get().n;
  const totalDay1 = db.prepare('SELECT COUNT(*) AS n FROM attempts WHERE day = 1 AND submitted = 1').get().n;
  const totalDay2 = db.prepare('SELECT COUNT(*) AS n FROM attempts WHERE day = 2 AND submitted = 1').get().n;
  const totalDay3 = db.prepare('SELECT COUNT(*) AS n FROM attempts WHERE day = 3 AND submitted = 1').get().n;
  const totalCompletedAll = db.prepare(`
    SELECT COUNT(*) AS n FROM (
      SELECT code FROM attempts WHERE submitted = 1 GROUP BY code HAVING COUNT(day) = 3
    )
  `).get().n;

  const students = db.prepare(`SELECT name, code, joined_at FROM students ORDER BY joined_at ASC`).all();

  const details = students.map(s => {
    const days = db.prepare('SELECT day, score, time_taken, submitted FROM attempts WHERE code = ?').all(s.code);
    const dayMap = { 1: null, 2: null, 3: null };
    days.forEach(d => { dayMap[d.day] = d; });
    const totalScore = days.filter(d => d.submitted).reduce((sum, d) => sum + (d.score || 0), 0);
    const totalTime = days.filter(d => d.submitted).reduce((sum, d) => sum + (d.time_taken || 0), 0);
    const daysDone = days.filter(d => d.submitted).length;
    return {
      name: s.name,
      code: s.code,
      joinedAt: s.joined_at,
      day1: dayMap[1] ? { score: dayMap[1].score, time: dayMap[1].time_taken, done: !!dayMap[1].submitted } : null,
      day2: dayMap[2] ? { score: dayMap[2].score, time: dayMap[2].time_taken, done: !!dayMap[2].submitted } : null,
      day3: dayMap[3] ? { score: dayMap[3].score, time: dayMap[3].time_taken, done: !!dayMap[3].submitted } : null,
      totalScore,
      totalTime,
      daysDone
    };
  });

  const leaderboard = [...details]
    .filter(s => s.daysDone === 3)
    .sort((a, b) => {
      if (b.totalScore !== a.totalScore) return b.totalScore - a.totalScore;
      return a.totalTime - b.totalTime;
    })
    .map((s, i) => ({ rank: i + 1, ...s }));

  res.json({
    stats: { totalJoined, totalDay1, totalDay2, totalDay3, totalCompletedAll },
    students: details,
    leaderboard
  });
});

// ============================================================
// CATCH-ALL
// ============================================================
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════╗');
  console.log('║   🚀 H.S.G. 3-Day Challenge Server Running          ║');
  console.log('╚═══════════════════════════════════════════════════╝');
  console.log('');
  console.log(`   👉 Open:          http://localhost:${PORT}`);
  console.log(`   🔐 Admin:         http://localhost:${PORT}/admin`);
  console.log(`   🔑 Admin password: ${ADMIN_PASSWORD}`);
  console.log('');
});
