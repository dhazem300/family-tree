// db.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.join(__dirname, "family.db");
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      person_id INTEGER NULL,
      display_name TEXT NULL,
      role_title TEXT DEFAULT 'مدير النظام',
      permissions TEXT DEFAULT '["all"]',
      is_super_admin INTEGER DEFAULT 1,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const adminExtraColumns = [
    ["person_id", "INTEGER NULL"],
    ["display_name", "TEXT NULL"],
    ["role_title", "TEXT DEFAULT 'مدير النظام'"],
    ["permissions", "TEXT DEFAULT '[\"all\"]'"],
    ["is_super_admin", "INTEGER DEFAULT 1"],
    ["is_active", "INTEGER DEFAULT 1"],
    ["created_at", "TEXT NULL"],
  ];

  db.all(`PRAGMA table_info(admins)`, (err, columns = []) => {
    if (err) return console.error("admins schema check error", err);
    const existing = new Set(columns.map((c) => c.name));
    adminExtraColumns.forEach(([name, definition]) => {
      if (!existing.has(name)) {
        db.run(`ALTER TABLE admins ADD COLUMN ${name} ${definition}`, (alterErr) => {
          if (alterErr) console.error(`admins add column ${name} error`, alterErr);
        });
      }
    });
    db.run(`UPDATE admins SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at = ''`, (updateErr) => {
      if (updateErr) console.error('admins created_at update error', updateErr);
    });
  });



  db.run(`
    CREATE TABLE IF NOT EXISTS admin_activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_id INTEGER,
      admin_username TEXT,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS site_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`INSERT OR IGNORE INTO site_settings (key, value, updated_at) VALUES ('maintenance_enabled', '0', CURRENT_TIMESTAMP)`);
  db.run(`INSERT OR IGNORE INTO site_settings (key, value, updated_at) VALUES ('maintenance_message', 'الموقع تحت الصيانة حاليًا، يرجى المحاولة لاحقًا.', CURRENT_TIMESTAMP)`);

  db.run(`
    CREATE TABLE IF NOT EXISTS person_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reference_code TEXT UNIQUE,
      name TEXT NOT NULL,
      gender TEXT,
      father_id INTEGER,
      mother_id INTEGER,
      birth_date TEXT,
      birth_place TEXT,
      death_date TEXT,
      death_place TEXT,
      is_deceased INTEGER DEFAULT 0,
      job TEXT,
      mobile_phone TEXT,
      personal_email TEXT,
      national_address TEXT,
      photo_url TEXT,
      notes TEXT,
      short_bio TEXT,
      spouse_names TEXT,
      children_names TEXT,
      payload_json TEXT,
      status TEXT DEFAULT 'pending',
      admin_note TEXT,
      created_person_id INTEGER,
      reviewed_by INTEGER,
      reviewed_at TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS persons (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      father_id INTEGER NULL,
      birth_date TEXT NULL,
      job TEXT NULL,
      mobile_phone TEXT NULL,
      personal_email TEXT NULL,
      national_address TEXT NULL,
      lineage TEXT NULL,
      photo_url TEXT NULL,
      notes TEXT NULL,
      FOREIGN KEY (father_id) REFERENCES persons(id)
    )
  `);
});

module.exports = db;
