const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'challenge.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS students (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    joined_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS attempts (
    code TEXT PRIMARY KEY,
    answers TEXT,
    score INTEGER,
    time_taken INTEGER,
    started_at INTEGER NOT NULL,
    submitted_at INTEGER,
    submitted INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// ⚠️ CHANGE THIS to your real challenge start time
const CHALLENGE_START_DATE = new Date('2026-09-10T08:00:00');

// ⚠️ CHANGE THIS to your secret PIN
const DEFAULT_PIN = '4268';

const pinRow = db.prepare('SELECT value FROM config WHERE key = ?').get('pin');
if (!pinRow) {
  db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run('pin', DEFAULT_PIN);
  console.log(`✅ PIN set (PIN: ${DEFAULT_PIN})`);
}

const startRow = db.prepare('SELECT value FROM config WHERE key = ?').get('challenge_start');
if (!startRow) {
  db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run(
    'challenge_start',
    CHALLENGE_START_DATE.getTime().toString()
  );
  console.log(`✅ Challenge start set: ${CHALLENGE_START_DATE.toISOString()}`);
}

module.exports = db;
