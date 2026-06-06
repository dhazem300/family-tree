require("dotenv").config();
const nodemailer = require("nodemailer");

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const db = require("./db");
const bcrypt = require("bcrypt");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const multer = require("multer");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: __dirname }),
    secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET",
    resave: false,
    saveUninitialized: false,
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Maintenance mode middleware. It is placed before static files so the public
// homepage cannot bypass maintenance mode by being served directly as index.html.
app.use(async (req, res, next) => {
  try {
    const isAdminArea = req.path.startsWith("/admin");
    const isAllowedAsset = req.path === "/theme.js" || req.path.startsWith("/assets/") || req.path.startsWith("/uploads/") || req.path.startsWith("/image-thumb/");
    if (isAdminArea || isAllowedAsset) return next();

    db.get(`SELECT value FROM site_settings WHERE key = 'maintenance_enabled'`, [], (err, row) => {
      if (err) return next();
      const enabled = String(row?.value || "0") === "1";
      if (!enabled) return next();

      db.get(`SELECT value FROM site_settings WHERE key = 'maintenance_message'`, [], (msgErr, msgRow) => {
        const message = msgRow?.value || "الموقع تحت الصيانة حاليًا، يرجى المحاولة لاحقًا.";
        if (req.path.startsWith("/api/")) return res.status(503).json({ ok: false, maintenance: true, message });
        return res.status(503).render("maintenance_public", { message });
      });
    });
  } catch (e) {
    return next();
  }
});

app.use(express.static(path.join(__dirname, "public")));


function findUploadedImageByName(filename) {
  const requested = path.basename(filename || "");
  if (!requested || requested.includes("..")) return null;
  const direct = path.join(uploadsDir, requested);
  if (fs.existsSync(direct) && fs.statSync(direct).isFile()) return direct;

  const prefixMatch = requested.match(/^(\d{10,})-/);
  if (!prefixMatch) return null;
  try {
    const found = fs.readdirSync(uploadsDir).find((name) => name.startsWith(prefixMatch[1] + "-"));
    if (found) return path.join(uploadsDir, found);
  } catch (e) {}
  return null;
}

// Fast thumbnails for tree cards. Existing uploaded photos are pre-generated
// into public/uploads/thumbs as small WebP files. If a thumbnail is missing,
// the original image is served as a safe fallback.
app.get("/image-thumb/:filename", (req, res, next) => {
  try {
    const requested = path.basename(req.params.filename || "");
    const source = findUploadedImageByName(requested);
    if (!source) return next();

    res.set("Cache-Control", "public, max-age=31536000, immutable");

    const safeName = requested.replace(/[^a-zA-Z0-9._-]/g, "_").replace(/\.[^.]+$/, "") || "thumb";
    const thumbPath = path.join(thumbsDir, safeName + ".webp");
    if (fs.existsSync(thumbPath)) return res.type("webp").sendFile(thumbPath);

    return res.sendFile(source);
  } catch (e) {
    return next();
  }
});

// Fallback for older uploaded image paths where Arabic filenames were encoded
// differently between the database value and the actual file on disk.
// If /uploads/<timestamp>-name.ext is not found exactly, serve the first file
// with the same timestamp prefix. This keeps legacy photos visible on Railway.
app.get("/uploads/:filename", (req, res, next) => {
  try {
    const requested = path.basename(req.params.filename || "");
    const direct = path.join(__dirname, "public", "uploads", requested);
    if (fs.existsSync(direct)) return res.sendFile(direct);

    const prefixMatch = requested.match(/^(\d{10,})-/);
    if (!prefixMatch) return next();

    const uploadsRoot = path.join(__dirname, "public", "uploads");
    const found = fs.readdirSync(uploadsRoot).find((name) => name.startsWith(prefixMatch[1] + "-"));
    if (found) return res.sendFile(path.join(uploadsRoot, found));
    return next();
  } catch (e) {
    return next();
  }
});

function parsePermissions(value) {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

const PERMISSION_GROUPS = [
  { key: "persons", label: "إدارة الأفراد", description: "إضافة وتعديل وحذف أفراد شجرة العائلة" },
  { key: "pages", label: "إدارة الصفحات", description: "تعديل صفحات النبذة، الدعم، وملفات PDF والخط الزمني" },
  { key: "honor", label: "السير الذاتية", description: "إضافة وتعديل وحذف كروت السير الذاتية" },
  { key: "news", label: "الأخبار والمناسبات", description: "كتابة وتعديل وحذف ونشر الأخبار" },
  { key: "comments", label: "تعليقات الأخبار", description: "متابعة وحذف تعليقات الأخبار" },
  { key: "subscribers", label: "مشتركو الأخبار", description: "إدارة وتصدير المشتركين في النشرة" },
  { key: "support", label: "رسائل الدعم", description: "عرض وحذف وتصدير رسائل الدعم" },
  { key: "roles", label: "وظائف وصلاحيات الأفراد", description: "تعيين أفراد العائلة كمستخدمين في الإدارة" },
  { key: "person_requests", label: "طلبات إضافة الأفراد", description: "مراجعة واعتماد بيانات الأفراد المرسلة من الزوار" },
];

function userCan(admin, permission) {
  if (!admin) return false;
  if (Number(admin.is_super_admin) === 1) return true;
  const permissions = parsePermissions(admin.permissions);
  return permissions.includes("all") || permissions.includes(permission);
}

function firstAllowedAdminPath(admin) {
  const map = {
    persons: "/admin",
    pages: "/admin/pages",
    honor: "/admin/honor",
    news: "/admin/news",
    comments: "/admin/news/comments",
    subscribers: "/admin/news/subscribers",
    support: "/admin/support-messages",
    roles: "/admin/roles",
    person_requests: "/admin/person-requests",
  };
  if (!admin) return "/admin/login";
  if (Number(admin.is_super_admin) === 1) return "/admin";
  const permissions = parsePermissions(admin.permissions);
  const first = permissions.find((p) => map[p]);
  return first ? map[first] : "/admin/no-access";
}

function isAuthed(req, res, next) {
  if (req.session?.admin) {
    res.locals.admin = req.session.admin;
    res.locals.userCan = (permission) => userCan(req.session.admin, permission);
    res.locals.permissionGroups = PERMISSION_GROUPS;
    return next();
  }
  return res.redirect("/admin/login");
}

function requirePermission(permission) {
  return function (req, res, next) {
    if (userCan(req.session?.admin, permission)) return next();
    return res.status(403).render("admin_no_access", {
      admin: req.session.admin,
      permissionGroups: PERMISSION_GROUPS,
      userCan: (perm) => userCan(req.session.admin, perm),
    });
  };
}

function requireSuperAdmin(req, res, next) {
  if (Number(req.session?.admin?.is_super_admin) === 1) return next();
  return res.status(403).render("admin_no_access", {
    admin: req.session.admin,
    permissionGroups: PERMISSION_GROUPS,
    userCan: (perm) => userCan(req.session.admin, perm),
  });
}

/* =========================
   Ensure folders
   ========================= */
const uploadsDir = path.join(__dirname, "public", "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });
const thumbsDir = path.join(__dirname, "public", "uploads", "thumbs");
fs.mkdirSync(thumbsDir, { recursive: true });

const pdfUploadsDir = path.join(__dirname, "public", "uploads", "pdfs");
fs.mkdirSync(pdfUploadsDir, { recursive: true });

/* =========================
   Multer uploads
   ========================= */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safe = Date.now() + "-" + String(file.originalname || "file").replace(/\s+/g, "_");
    cb(null, safe);
  },
});
const upload = multer({ storage });

const pdfStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, pdfUploadsDir),
  filename: (req, file, cb) => {
    const safeOriginal = String(file.originalname || "file.pdf").replace(/\s+/g, "_");
    const safe = Date.now() + "-" + safeOriginal;
    cb(null, safe);
  },
});
function pdfFileFilter(req, file, cb) {
  const okByMime = file.mimetype === "application/pdf";
  const okByName = /\.pdf$/i.test(file.originalname || "");
  if (okByMime || okByName) return cb(null, true);
  cb(new Error("Only PDF files are allowed"));
}
const uploadPdf = multer({
  storage: pdfStorage,
  fileFilter: pdfFileFilter,
  limits: { fileSize: 25 * 1024 * 1024 },
});

/* =========================
   DB helpers
   ========================= */
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      err ? reject(err) : resolve(this);
    });
  });
}


async function ensureAdminRoleSchema() {
  const columns = await all(`PRAGMA table_info(admins)`);
  const existing = new Set(columns.map((c) => c.name));
  const needed = [
    ["person_id", "INTEGER NULL"],
    ["display_name", "TEXT NULL"],
    ["role_title", "TEXT DEFAULT 'مدير النظام'"],
    ["permissions", "TEXT DEFAULT '[\"all\"]'"],
    ["is_super_admin", "INTEGER DEFAULT 0"],
    ["is_active", "INTEGER DEFAULT 1"],
    ["created_at", "TEXT NULL"],
  ];

  for (const [name, definition] of needed) {
    if (!existing.has(name)) {
      await run(`ALTER TABLE admins ADD COLUMN ${name} ${definition}`);
    }
  }

  const firstAdmin = await get(`SELECT id FROM admins ORDER BY id ASC LIMIT 1`);
  if (firstAdmin) {
    await run(
      `UPDATE admins
       SET is_super_admin = 1,
           is_active = COALESCE(is_active, 1),
           permissions = CASE WHEN permissions IS NULL OR permissions = '' THEN '["all"]' ELSE permissions END,
           role_title = CASE WHEN role_title IS NULL OR role_title = '' THEN 'مدير النظام' ELSE role_title END
       WHERE id = ?`,
      [firstAdmin.id]
    );
  }

  await run(`UPDATE admins SET is_active = 1 WHERE is_active IS NULL`);
  await run(`UPDATE admins SET permissions = '["all"]' WHERE is_super_admin = 1 AND (permissions IS NULL OR permissions = '')`);
  await run(`UPDATE admins SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at = ''`);
}

function normalizeMulti(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  return [value];
}

async function logAdminAction(req, action, entityType = "", entityId = "", details = {}) {
  try {
    await ensureAdminEnhancements();
    const admin = req.session?.admin || null;
    await run(
      `INSERT INTO admin_activity_logs
       (admin_id, admin_username, action, entity_type, entity_id, details, ip_address, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [
        admin?.id || null,
        admin?.username || req.body?.username || "غير معروف",
        action,
        entityType || "",
        entityId != null ? String(entityId) : "",
        JSON.stringify(details || {}),
        getClientIp(req),
        String(req.headers["user-agent"] || "").slice(0, 300),
      ]
    );
  } catch (e) {
    console.error("admin activity log error:", e.message || e);
  }
}

function parseLogDetails(details) {
  try { return JSON.parse(details || "{}"); } catch (e) { return {}; }
}

/* =========================
   Protection Helpers
   ========================= */
function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    req.ip ||
    "unknown"
  );
}

function cleanText(value, max = 1000) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function hasLinks(text) {
  return /(https?:\/\/|www\.|\.com|\.net|\.org|\.info|\.xyz|\.ru|\.io)/i.test(String(text || ""));
}

const likeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const commentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

/* =========================
   Persons helpers
   ========================= */
async function ensureColumn(tableName, columnName, sqlTypeAndDefault) {
  const cols = await all(`PRAGMA table_info(${tableName})`);
  const exists = cols.some((c) => c.name === columnName);
  if (!exists) {
    await run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${sqlTypeAndDefault}`);
  }
}

async function ensurePersonsColumns() {
  try {
    await ensureColumn("persons", "gender", "TEXT");
    await ensureColumn("persons", "mother_id", "INTEGER");
    await ensureColumn("persons", "birth_place", "TEXT");
    await ensureColumn("persons", "death_date", "TEXT");
    await ensureColumn("persons", "death_place", "TEXT");
    await ensureColumn("persons", "is_deceased", "INTEGER DEFAULT 0");
    await ensureColumn("persons", "short_bio", "TEXT");
    await ensureColumn("persons", "mobile_phone", "TEXT");
    await ensureColumn("persons", "personal_email", "TEXT");
    await ensureColumn("persons", "national_address", "TEXT");
    await ensureColumn("persons", "education_level", "TEXT");

    await ensureColumn("persons", "photo_url", "TEXT");
    await ensureColumn("persons", "notes", "TEXT");
    await ensureColumn("persons", "job", "TEXT");
    await ensureColumn("persons", "lineage", "TEXT");
    await ensureColumn("persons", "birth_date", "TEXT");
    await ensureColumn("persons", "father_id", "INTEGER");
  } catch (e) {
    console.error("ensurePersonsColumns error:", e);
  }
}

async function ensureCmsTables() {
  await run(`
    CREATE TABLE IF NOT EXISTS site_pages (
      slug TEXT PRIMARY KEY,
      title TEXT,
      subtitle TEXT,
      content TEXT,
      updated_at TEXT
    )
  `);

  try {
    await ensureColumn("site_pages", "pdf_url", "TEXT");
    await ensureColumn("site_pages", "fund_name", "TEXT");
    await ensureColumn("site_pages", "bank_name", "TEXT");
    await ensureColumn("site_pages", "account_number", "TEXT");
    await ensureColumn("site_pages", "whatsapp", "TEXT");
    await ensureColumn("site_pages", "email", "TEXT");
  } catch (e) {
    console.error("site_pages columns ensure error:", e);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS honor_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      person_id INTEGER,
      name TEXT NOT NULL,
      field TEXT,
      achievement TEXT,
      photo_url TEXT,
      ord INTEGER DEFAULT 1
    )
  `);

  try {
    await ensureColumn("honor_items", "bio", "TEXT");
    await ensureColumn("honor_items", "person_id", "INTEGER");
    await ensureColumn("honor_items", "birth_date", "TEXT");
    await ensureColumn("honor_items", "death_date", "TEXT");
    await ensureColumn("honor_items", "birth_place", "TEXT");
  } catch (e) {
    console.error("honor_items columns ensure error:", e);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS support_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_name TEXT,
      phone TEXT,
      message TEXT,
      created_at TEXT
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS news_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      summary TEXT,
      content TEXT,
      image_url TEXT,
      person_id INTEGER,
      event_date TEXT,
      published_at TEXT DEFAULT CURRENT_TIMESTAMP,
      is_active INTEGER DEFAULT 1,
      is_pinned INTEGER DEFAULT 0,
      views_count INTEGER DEFAULT 0,
      notify_enabled INTEGER DEFAULT 0,
      publisher_name TEXT,
      publisher_phone TEXT
    )
  `);

  try {
    await ensureColumn("news_posts", "person_id", "INTEGER");
    await ensureColumn("news_posts", "event_date", "TEXT");
    await ensureColumn("news_posts", "published_at", "TEXT DEFAULT CURRENT_TIMESTAMP");
    await ensureColumn("news_posts", "is_active", "INTEGER DEFAULT 1");
    await ensureColumn("news_posts", "is_pinned", "INTEGER DEFAULT 0");
    await ensureColumn("news_posts", "views_count", "INTEGER DEFAULT 0");
    await ensureColumn("news_posts", "notify_enabled", "INTEGER DEFAULT 0");
    await ensureColumn("news_posts", "publisher_name", "TEXT");
    await ensureColumn("news_posts", "publisher_phone", "TEXT");
  } catch (e) {
    console.error("news_posts columns ensure error:", e);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS newsletter_subscribers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      is_active INTEGER DEFAULT 1
    )
  `);

  try {
    await ensureColumn("newsletter_subscribers", "subscriber_name", "TEXT");
    await ensureColumn("newsletter_subscribers", "is_active", "INTEGER DEFAULT 1");
  } catch (e) {
    console.error("newsletter_subscribers columns ensure error:", e);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS news_notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      news_id INTEGER NOT NULL,
      title TEXT,
      message TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      is_active INTEGER DEFAULT 1
    )
  `);

  try {
    await ensureColumn("news_notifications", "message", "TEXT");
    await ensureColumn("news_notifications", "is_active", "INTEGER DEFAULT 1");
  } catch (e) {
    console.error("news_notifications columns ensure error:", e);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS news_likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS news_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER,
      name TEXT,
      content TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  try {
    await ensureColumn("news_likes", "ip_address", "TEXT");
    await ensureColumn("news_comments", "ip_address", "TEXT");
  } catch (e) {
    console.error("news likes/comments columns ensure error:", e);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS timeline_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      description TEXT,
      date TEXT,
      image_url TEXT,
      "order" INTEGER DEFAULT 0,
      visible INTEGER DEFAULT 1
    )
  `);

  const seeds = [
    {
      slug: "about",
      title: "نبذة عن العائلة",
      subtitle: "لمحة تاريخية مختصرة عن الجذور والمسار",
      content: "",
    },
    {
      slug: "support",
      title: "الدعم والشكاوى",
      subtitle: "أرسل اقتراحك أو بلاغك وسيتم مراجعته",
      content: "",
    },
    {
      slug: "tree-pdf",
      title: "شجرة العائلة PDF",
      subtitle: "عرض التصميم الرسمي داخل برواز مزخرف",
      content: "",
    },
  ];

  for (const s of seeds) {
    const exists = await get(`SELECT slug FROM site_pages WHERE slug = ?`, [s.slug]);
    if (!exists) {
      await run(
        `INSERT INTO site_pages (
          slug, title, subtitle, content, updated_at, pdf_url,
          fund_name, bank_name, account_number, whatsapp, email
        )
        VALUES (?, ?, ?, ?, datetime('now'), NULL, '', '', '', '', '')`,
        [s.slug, s.title, s.subtitle, s.content]
      );
    }
  }
}

async function ensureSpousesTable() {
  await run(`
    CREATE TABLE IF NOT EXISTS person_spouses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      person_id INTEGER NOT NULL,
      spouse_name TEXT NOT NULL,
      ord INTEGER DEFAULT 1
    )
  `);
}

async function ensurePersonRequestsTable() {
  await run(`
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
      education_level TEXT,
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

  const cols = await all(`PRAGMA table_info(person_requests)`);
  const existing = new Set(cols.map((c) => c.name));
  const extraCols = [
    ["reference_code", "TEXT"],
    ["education_level", "TEXT"],
    ["father_lineage_name", "TEXT"],
    ["mother_lineage_name", "TEXT"],
    ["payload_json", "TEXT"],
    ["status", "TEXT DEFAULT 'pending'"],
    ["admin_note", "TEXT"],
    ["created_person_id", "INTEGER"],
    ["reviewed_by", "INTEGER"],
    ["reviewed_at", "TEXT"],
    ["ip_address", "TEXT"],
    ["user_agent", "TEXT"],
    ["created_at", "TEXT DEFAULT CURRENT_TIMESTAMP"],
  ];
  for (const [col, definition] of extraCols) {
    if (!existing.has(col)) await ensureColumn("person_requests", col, definition);
  }
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_person_requests_reference_code ON person_requests(reference_code)`);
}

async function ensureAdminEnhancements() {
  await run(`
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

  await run(`
    CREATE TABLE IF NOT EXISTS site_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const defaults = [
    ["maintenance_enabled", "0"],
    ["maintenance_message", "الموقع تحت الصيانة حاليًا، يرجى المحاولة لاحقًا."],
  ];
  for (const [key, value] of defaults) {
    const exists = await get(`SELECT key FROM site_settings WHERE key=?`, [key]);
    if (!exists) {
      await run(`INSERT INTO site_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, [key, value]);
    }
  }
}

async function bootstrap() {
  await ensurePersonsColumns();
  await ensureCmsTables();
  await ensureSpousesTable();
  await ensurePersonRequestsTable();
  await ensureAdminEnhancements();
}
bootstrap().catch((err) => console.error("Bootstrap error:", err));

/* =========================
   spouse names helpers
   ========================= */
async function getSpouseNames(personId) {
  return all(
    `SELECT spouse_name, ord
     FROM person_spouses
     WHERE person_id = ?
     ORDER BY ord ASC, id ASC`,
    [personId]
  );
}

async function setSpouseNames(personId, names) {
  await run(`DELETE FROM person_spouses WHERE person_id = ?`, [personId]);

  const cleaned = normalizeMulti(names)
    .map((s) => String(s || "").trim())
    .filter(Boolean);

  let ord = 1;
  for (const nm of cleaned) {
    await run(
      `INSERT INTO person_spouses (person_id, spouse_name, ord)
       VALUES (?, ?, ?)`,
      [personId, nm, ord]
    );
    ord++;
  }
}

function linesToCleanArray(value, maxItems = 30, maxLen = 160) {
  if (Array.isArray(value)) return value.map((x) => cleanText(x, maxLen)).filter(Boolean).slice(0, maxItems);
  return String(value || "")
    .split(/\r?\n|\|/g)
    .map((x) => cleanText(x, maxLen))
    .filter(Boolean)
    .slice(0, maxItems);
}

function listToTextarea(value) {
  if (!value) return "";
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.join("\n");
  } catch (e) {}
  return String(value || "");
}


function normalizeArabicForMatch(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[أإآٱ]/g, "ا")
    .replace(/ى/g, "ي")
    .replace(/ة/g, "ه")
    .replace(/ؤ/g, "و")
    .replace(/ئ/g, "ي")
    .replace(/[ًٌٍَُِّْـ]/g, "")
    .replace(/[.,،؛:!؟()\[\]{}"'`~@#$%^&*_+=<>/\\|-]/g, " ")
    .replace(/\b(بن|ابن|بنت|ال)\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function namePartsForMatch(value) {
  return normalizeArabicForMatch(value).split(" ").filter(Boolean);
}

function firstNameForMatch(value) {
  return namePartsForMatch(value)[0] || "";
}

function buildThreePartLineage(person, byId) {
  if (!person) return "";
  const first = firstNameForMatch(person.name);
  const father = person.father_id ? byId.get(Number(person.father_id)) : null;
  const fatherFirst = father ? firstNameForMatch(father.name) : "";
  const grandfather = father && father.father_id ? byId.get(Number(father.father_id)) : null;
  const grandfatherFirst = grandfather ? firstNameForMatch(grandfather.name) : "";
  return [first, fatherFirst, grandfatherFirst].filter(Boolean).join(" ");
}

async function getPersonsForLineage(excludeId = null) {
  const rows = await all(`SELECT id, name, father_id, mother_id, gender FROM persons ORDER BY id ASC`);
  const byId = new Map(rows.map((r) => [Number(r.id), r]));
  const usable = excludeId ? rows.filter((r) => Number(r.id) !== Number(excludeId)) : rows;
  return { rows: usable, byId };
}

async function resolvePersonByThreePartLineage(input, options = {}) {
  const q = cleanText(input, 220);
  const parts = namePartsForMatch(q);
  if (!q || parts.length < 3) {
    return { ok: false, id: null, status: "empty", message: "اكتب الاسم الثلاثي مثل: حجاج يوسف حسن" };
  }

  const target = parts.slice(0, 3);
  const { rows, byId } = await getPersonsForLineage(options.excludeId || null);
  const matches = [];

  for (const person of rows) {
    const father = person.father_id ? byId.get(Number(person.father_id)) : null;
    const grandfather = father && father.father_id ? byId.get(Number(father.father_id)) : null;
    if (!father || !grandfather) continue;

    const triple = [firstNameForMatch(person.name), firstNameForMatch(father.name), firstNameForMatch(grandfather.name)];
    if (triple[0] === target[0] && triple[1] === target[1] && triple[2] === target[2]) {
      if (options.gender && normalizeArabicForMatch(person.gender) && normalizeArabicForMatch(person.gender) !== normalizeArabicForMatch(options.gender)) {
        // لا نمنع المطابقة بسبب اختلاف صيغة النوع، فقط نستمر لو الطلب محدد بشدة.
      }
      matches.push({
        id: person.id,
        name: person.name,
        lineage: buildThreePartLineage(person, byId),
      });
    }
  }

  if (matches.length === 1) return { ok: true, id: matches[0].id, status: "matched", match: matches[0] };
  if (matches.length > 1) return { ok: false, id: null, status: "multiple", matches, message: "يوجد أكثر من شخص بنفس التسلسل، يرجى توضيح الاسم أكثر من الإدارة." };
  return { ok: false, id: null, status: "not_found", message: "لم يتم العثور على شخص بهذا التسلسل الثلاثي داخل الشجرة." };
}

async function lineageLabelForPersonId(personId) {
  if (!personId) return "";
  const { rows, byId } = await getPersonsForLineage();
  const person = byId.get(Number(personId));
  return buildThreePartLineage(person, byId);
}

async function resolveOptionalLineageId(value, options = {}) {
  const q = cleanText(value, 220);
  if (!q) return { id: null, text: "", result: null };
  const result = await resolvePersonByThreePartLineage(q, options);
  return { id: result.ok ? result.id : null, text: q, result };
}

async function getRequestCounts() {
  const rows = await all(`SELECT status, COUNT(*) AS total FROM person_requests GROUP BY status`);
  const out = { pending: 0, approved: 0, rejected: 0, total: 0 };
  rows.forEach((r) => {
    out[r.status || "pending"] = Number(r.total || 0);
    out.total += Number(r.total || 0);
  });
  return out;
}

/* =========================
   Tree builder
   ========================= */
function buildTree(rows) {
  const byId = new Map(
    rows.map((r) => [
      r.id,
      {
        ...r,
        children: [],
      },
    ])
  );

  let root = null;

  for (const r of byId.values()) {
    if (r.father_id) {
      const parent = byId.get(r.father_id);
      if (parent) parent.children.push(r);
      else if (!root) root = r;
    } else if (!root) {
      root = r;
    }
  }

  return root;
}

/* =========================
   Stats helpers
   ========================= */
async function getSiteStats() {
  const totalRow = await get(`SELECT COUNT(*) AS total FROM persons`);
  const malesRow = await get(
    `SELECT COUNT(*) AS total
     FROM persons
     WHERE LOWER(TRIM(COALESCE(gender, ''))) IN ('male', 'm', 'ذكر', 'رجل')`
  );
  const femalesRow = await get(
    `SELECT COUNT(*) AS total
     FROM persons
     WHERE LOWER(TRIM(COALESCE(gender, ''))) IN ('female', 'f', 'أنثى', 'انثى', 'امرأة', 'إمرأة', 'بنت')`
  );

  // لا نعتبر كل من ليس عليه علامة "متوفى" أنه حي؛ لأن كثيرًا من السجلات القديمة قد تكون حالتها غير مدخلة.
  // لذلك الإحصائية الأدق هنا هي "المتوفون المسجلون"، والحالة غير المحددة تُحسب بشكل مستقل.
  const deceasedRow = await get(
    `SELECT COUNT(*) AS total
     FROM persons
     WHERE COALESCE(is_deceased, 0) = 1
        OR TRIM(COALESCE(death_date, '')) <> ''`
  );

  const repeatedNames = await all(`
    SELECT
      TRIM(name) AS name,
      COUNT(*) AS count
    FROM persons
    WHERE TRIM(COALESCE(name, '')) <> ''
    GROUP BY TRIM(name)
    HAVING COUNT(*) > 1
    ORDER BY COUNT(*) DESC, name ASC
  `);

  const newsRow = await get(`SELECT COUNT(*) AS total FROM news_posts`);
  const activeNewsRow = await get(`SELECT COUNT(*) AS total FROM news_posts WHERE COALESCE(is_active, 1) = 1`);
  const inactiveNewsRow = await get(`SELECT COUNT(*) AS total FROM news_posts WHERE COALESCE(is_active, 1) = 0`);
  const supportRow = await get(`SELECT COUNT(*) AS total FROM support_messages`);
  const honorRow = await get(`SELECT COUNT(*) AS total FROM honor_items`);
  const adminsRow = await get(`SELECT COUNT(*) AS total FROM admins WHERE COALESCE(is_active, 1) = 1`);
  const noPhotoRow = await get(`SELECT COUNT(*) AS total FROM persons WHERE TRIM(COALESCE(photo_url, '')) = ''`);
  const noBioRow = await get(`SELECT COUNT(*) AS total FROM persons WHERE TRIM(COALESCE(short_bio, '')) = '' AND TRIM(COALESCE(notes, '')) = ''`);
  const noBirthRow = await get(`SELECT COUNT(*) AS total FROM persons WHERE TRIM(COALESCE(birth_date, '')) = ''`);

  const total = Number(totalRow?.total || 0);
  const males = Number(malesRow?.total || 0);
  const females = Number(femalesRow?.total || 0);
  const deceased = Number(deceasedRow?.total || 0);
  const noPhoto = Number(noPhotoRow?.total || 0);
  const noBio = Number(noBioRow?.total || 0);
  const noBirth = Number(noBirthRow?.total || 0);

  return {
    total,
    males,
    females,
    unknownGender: Math.max(total - males - females, 0),
    // kept for older views that may still reference alive, but the dashboard no longer labels it as "الأحياء".
    alive: Math.max(total - deceased, 0),
    deceased,
    unknownStatus: Math.max(total - deceased, 0),
    newsTotal: Number(newsRow?.total || 0),
    activeNews: Number(activeNewsRow?.total || 0),
    inactiveNews: Number(inactiveNewsRow?.total || 0),
    supportTotal: Number(supportRow?.total || 0),
    honorTotal: Number(honorRow?.total || 0),
    activeAdmins: Number(adminsRow?.total || 0),
    noPhoto,
    withPhoto: Math.max(total - noPhoto, 0),
    noBio,
    withBio: Math.max(total - noBio, 0),
    noBirth,
    withBirth: Math.max(total - noBirth, 0),
    repeatedNames,
    repeatedCount: repeatedNames.length,
    repeatedPeopleCount: repeatedNames.reduce((sum, item) => sum + Number(item.count || 0), 0),
  };
}

async function getFullDashboardData() {
  const stats = await getSiteStats();
  const latestPersons = await all(`SELECT id, name, gender, birth_date, photo_url FROM persons ORDER BY id DESC LIMIT 10`);
  const latestNews = await all(`SELECT id, title, published_at, is_active, views_count FROM news_posts ORDER BY id DESC LIMIT 10`);
  const latestSupport = await all(`SELECT id, sender_name, phone, created_at FROM support_messages ORDER BY id DESC LIMIT 10`);
  const latestActivity = await all(`SELECT * FROM admin_activity_logs ORDER BY id DESC LIMIT 10`);
  const maintenance = await get(`SELECT value FROM site_settings WHERE key='maintenance_enabled'`);
  return {
    stats,
    latestPersons,
    latestNews,
    latestSupport,
    latestActivity,
    maintenanceEnabled: String(maintenance?.value || "0") === "1",
  };
}

async function getPersonStatsPageData() {
  const stats = await getSiteStats();

  const recentPersons = await all(`
    SELECT id, name, gender, is_deceased
    FROM persons
    ORDER BY id DESC
    LIMIT 10
  `);

  const malePercent = stats.total ? Math.round((stats.males / stats.total) * 100) : 0;
  const femalePercent = stats.total ? Math.round((stats.females / stats.total) * 100) : 0;
  const alivePercent = stats.total ? Math.round((stats.alive / stats.total) * 100) : 0;
  const deceasedPercent = stats.total ? Math.round((stats.deceased / stats.total) * 100) : 0;

  return {
    ...stats,
    recentPersons,
    malePercent,
    femalePercent,
    alivePercent,
    deceasedPercent,
  };
}

async function getAdminDashboardStats() {
  const newsTotal = await get(`SELECT COUNT(*) AS total FROM news_posts`);
  const newsPublished = await get(`
    SELECT COUNT(*) AS total
    FROM news_posts
    WHERE COALESCE(is_active, 1) = 1
  `);

  const viewsTotal = await get(`
    SELECT COALESCE(SUM(COALESCE(views_count, 0)), 0) AS total
    FROM news_posts
  `);

  const likesTotal = await get(`
    SELECT COUNT(*) AS total
    FROM news_likes
  `);

  const commentsTotal = await get(`
    SELECT COUNT(*) AS total
    FROM news_comments
  `);

  const subscribersTotal = await get(`
    SELECT COUNT(*) AS total
    FROM newsletter_subscribers
  `);

  const subscribersActive = await get(`
    SELECT COUNT(*) AS total
    FROM newsletter_subscribers
    WHERE COALESCE(is_active, 1) = 1
  `);

  const topNews = await all(`
    SELECT
      n.id,
      n.title,
      COALESCE(n.views_count, 0) AS views_count,
      (
        SELECT COUNT(*)
        FROM news_likes l
        WHERE l.post_id = n.id
      ) AS likes_count,
      (
        SELECT COUNT(*)
        FROM news_comments c
        WHERE c.post_id = n.id
      ) AS comments_count
    FROM news_posts n
    ORDER BY COALESCE(n.views_count, 0) DESC, n.id DESC
    LIMIT 5
  `);

  const latestComments = await all(`
    SELECT
      c.id,
      c.post_id,
      c.name,
      c.content,
      c.created_at,
      n.title AS news_title
    FROM news_comments c
    LEFT JOIN news_posts n ON n.id = c.post_id
    ORDER BY c.id DESC
    LIMIT 5
  `);

  return {
    newsTotal: newsTotal?.total || 0,
    newsPublished: newsPublished?.total || 0,
    viewsTotal: viewsTotal?.total || 0,
    likesTotal: likesTotal?.total || 0,
    commentsTotal: commentsTotal?.total || 0,
    subscribersTotal: subscribersTotal?.total || 0,
    subscribersActive: subscribersActive?.total || 0,
    topNews,
    latestComments,
  };
}

async function getNewsStatsPageData() {
  const dashboard = await getAdminDashboardStats();

  const pinned = await get(`
    SELECT COUNT(*) AS total
    FROM news_posts
    WHERE COALESCE(is_pinned, 0) = 1
  `);

  const hidden = await get(`
    SELECT COUNT(*) AS total
    FROM news_posts
    WHERE COALESCE(is_active, 1) = 0
  `);

  const notifications = await get(`
    SELECT COUNT(*) AS total
    FROM news_notifications
  `);

  return {
    ...dashboard,
    pinned: pinned?.total || 0,
    hidden: hidden?.total || 0,
    notifications: notifications?.total || 0,
  };
}

async function resolvePersonIdByName(name) {
  const clean = String(name || "").trim();
  if (!clean) return null;

  const row = await get(
    `SELECT id FROM persons WHERE TRIM(name) = ? ORDER BY id ASC LIMIT 1`,
    [clean]
  );

  return row?.id || null;
}

async function getPublicHonorItems() {
  return all(`
    SELECT
      COALESCE(h.person_id, p.id, h.id) AS id,
      h.id AS honor_id,
      COALESCE(h.person_id, p.id) AS person_id,
      COALESCE(NULLIF(TRIM(h.name), ''), p.name, '') AS name,
      COALESCE(NULLIF(TRIM(h.field), ''), p.job, '') AS field,
      COALESCE(NULLIF(TRIM(h.achievement), ''), p.notes, '') AS achievement,
      COALESCE(NULLIF(TRIM(h.bio), ''), p.short_bio, p.notes, '') AS bio,
      COALESCE(NULLIF(TRIM(h.birth_date), ''), p.birth_date, '') AS birth_date,
      COALESCE(NULLIF(TRIM(h.death_date), ''), p.death_date, '') AS death_date,
      COALESCE(NULLIF(TRIM(h.birth_place), ''), p.birth_place, '') AS birth_place,
      COALESCE(NULLIF(TRIM(h.photo_url), ''), p.photo_url, '') AS photo_url,
      h.ord AS ord
    FROM honor_items h
    LEFT JOIN persons linked
      ON linked.id = h.person_id
    LEFT JOIN persons p
      ON p.id = COALESCE(h.person_id, linked.id)
      OR (
        h.person_id IS NULL
        AND TRIM(p.name) = TRIM(h.name)
      )
    GROUP BY h.id
    ORDER BY h.ord ASC, h.id ASC
  `);
}

async function getPublicNews(limit = 12) {
  return all(
    `SELECT
       n.*,
       p.name AS person_name,
       p.photo_url AS person_photo_url
     FROM news_posts n
     LEFT JOIN persons p ON p.id = n.person_id
     WHERE COALESCE(n.is_active, 1) = 1
     ORDER BY
       COALESCE(n.is_pinned, 0) DESC,
       COALESCE(NULLIF(n.event_date, ''), n.published_at, datetime('now')) DESC,
       n.id DESC
     LIMIT ?`,
    [Number(limit || 12)]
  );
}

async function getAllNewsAdmin() {
  return all(`
    SELECT
      n.*,
      p.name AS person_name,
      p.photo_url AS person_photo_url,
      (
        SELECT COUNT(*)
        FROM news_likes l
        WHERE l.post_id = n.id
      ) AS likes_count,
      (
        SELECT COUNT(*)
        FROM news_comments c
        WHERE c.post_id = n.id
      ) AS comments_count
    FROM news_posts n
    LEFT JOIN persons p ON p.id = n.person_id
    ORDER BY COALESCE(n.is_pinned, 0) DESC, n.id DESC
  `);
}

async function getPublicTimelineItems() {
  return all(`
    SELECT *
    FROM timeline_events
    WHERE visible = 1
    ORDER BY "order" ASC, id ASC
  `);
}

async function getRelatedNews(newsId, limit = 3) {
  const current = await get(`SELECT person_id FROM news_posts WHERE id = ?`, [newsId]);
  const params = [];

  let preferredCondition = "";
  if (current?.person_id) {
    preferredCondition = "CASE WHEN n.person_id = ? THEN 0 ELSE 1 END,";
    params.push(current.person_id);
  }

  params.push(newsId, Number(limit || 3));

  return all(
    `SELECT
       n.*,
       p.name AS person_name,
       p.photo_url AS person_photo_url
     FROM news_posts n
     LEFT JOIN persons p ON p.id = n.person_id
     WHERE COALESCE(n.is_active, 1) = 1
       AND n.id != ?
     ORDER BY
       ${preferredCondition}
       COALESCE(n.is_pinned, 0) DESC,
       COALESCE(NULLIF(n.event_date, ''), n.published_at, datetime('now')) DESC,
       n.id DESC
     LIMIT ?`,
    params
  );
}

async function createNewsNotification(newsId, title, summary) {
  await run(
    `INSERT INTO news_notifications (news_id, title, message, created_at, is_active)
     VALUES (?, ?, ?, datetime('now'), 1)`,
    [newsId, String(title || "").trim(), String(summary || "").trim()]
  );
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());
}


/* =========================
   Public relationship and assistant helpers
   ========================= */
function genderIsFemale(person) {
  const g = normalizeArabicForMatch(person?.gender || "");
  return ["female", "f", "انثي", "امراه", "بنت"].includes(g);
}

function genderIsMale(person) {
  const g = normalizeArabicForMatch(person?.gender || "");
  return ["male", "m", "ذكر", "رجل"].includes(g);
}

function childLabel(child) {
  return genderIsFemale(child) ? "ابنة" : "ابن";
}

function parentLabel(parent) {
  return genderIsFemale(parent) ? "الأم" : "الأب";
}

function ancestorLabel(ancestor, distance) {
  if (distance === 1) return genderIsFemale(ancestor) ? "الأم" : "الأب";
  if (distance === 2) return genderIsFemale(ancestor) ? "الجدة" : "الجد";
  return genderIsFemale(ancestor) ? `الجدة من الدرجة ${distance - 1}` : `الجد من الدرجة ${distance - 1}`;
}

function descendantLabel(descendant, distance) {
  if (distance === 1) return genderIsFemale(descendant) ? "الابنة" : "الابن";
  if (distance === 2) return genderIsFemale(descendant) ? "الحفيدة" : "الحفيد";
  return genderIsFemale(descendant) ? `حفيدة من الدرجة ${distance - 1}` : `حفيد من الدرجة ${distance - 1}`;
}

async function getPersonsForRelationship() {
  const rows = await all(`SELECT id, name, father_id, mother_id, gender, birth_date, death_date, birth_place, photo_url, job, education_level, short_bio, notes FROM persons ORDER BY id ASC`);
  const byId = new Map(rows.map((r) => [Number(r.id), { ...r, id: Number(r.id) }]));
  return { rows: rows.map((r) => ({ ...r, id: Number(r.id) })), byId };
}

function lineagePhraseForPerson(person, byId, max = 4) {
  const out = [];
  let current = person;
  for (let i = 0; i < max && current; i++) {
    const first = firstNameForMatch(current.name);
    if (first) out.push(first);
    current = current.father_id ? byId.get(Number(current.father_id)) : null;
  }
  return out.join(" ");
}

function matchPersonByFlexibleName(query, rows, byId) {
  const q = normalizeArabicForMatch(query);
  const parts = namePartsForMatch(query);
  if (!q || parts.length < 1) return { status: "empty", matches: [] };

  const scored = [];
  for (const person of rows) {
    const full = normalizeArabicForMatch(person.name);
    const lineage3 = normalizeArabicForMatch(lineagePhraseForPerson(person, byId, 3));
    const lineage4 = normalizeArabicForMatch(lineagePhraseForPerson(person, byId, 4));
    let score = 0;
    if (full === q) score = 100;
    else if (lineage4 === q) score = 98;
    else if (lineage3 === q) score = 95;
    else if (q.length >= 3 && (full.includes(q) || lineage4.includes(q))) score = 60;
    else {
      const lineageParts = lineage4.split(" ").filter(Boolean);
      const ok = parts.every((part, i) => lineageParts[i] === part || full.split(" ").includes(part));
      if (ok) score = 40;
    }
    if (score) scored.push({ ...person, match_score: score, lineage_label: lineagePhraseForPerson(person, byId, 4) });
  }
  scored.sort((a,b)=> b.match_score - a.match_score || Number(a.id)-Number(b.id));
  const topScore = scored[0]?.match_score || 0;
  const top = scored.filter((x)=>x.match_score === topScore).slice(0, 8);
  return { status: top.length === 1 ? "matched" : top.length > 1 ? "multiple" : "not_found", matches: top };
}

function ancestorMap(person, byId) {
  const map = new Map();
  function walk(node, dist, path) {
    if (!node || map.has(Number(node.id))) return;
    map.set(Number(node.id), { person: node, distance: dist, path: [...path, node] });
    const father = node.father_id ? byId.get(Number(node.father_id)) : null;
    const mother = node.mother_id ? byId.get(Number(node.mother_id)) : null;
    if (father) walk(father, dist + 1, [...path, node]);
    if (mother) walk(mother, dist + 1, [...path, node]);
  }
  walk(person, 0, []);
  return map;
}

function personPathText(path) {
  return path.map((p)=>p.name).join(" ← ");
}

function describeKinship(a, b, byId) {
  if (!a || !b) return { ok:false, message:"لم يتم العثور على أحد الشخصين." };
  if (Number(a.id) === Number(b.id)) {
    return { ok:true, message:`${a.name} و ${b.name} هما نفس الشخص داخل الشجرة.`, path:[a] };
  }

  const aAnc = ancestorMap(a, byId);
  const bAnc = ancestorMap(b, byId);
  let best = null;
  for (const [id, va] of aAnc.entries()) {
    const vb = bAnc.get(id);
    if (!vb) continue;
    const total = va.distance + vb.distance;
    if (!best || total < best.total) best = { id, common: va.person, a: va, b: vb, total };
  }

  if (!best) return { ok:false, message:"لا توجد صلة قرابة واضحة بين الاسمين داخل البيانات الحالية للشجرة." };
  const dA = best.a.distance;
  const dB = best.b.distance;
  const common = best.common;
  const fullPath = [...best.a.path, common, ...best.b.path.slice(0, -1).reverse()].filter(Boolean);

  let relation = "";
  if (dA === 0) {
    relation = `${a.name} هو ${ancestorLabel(a, dB)} بالنسبة إلى ${b.name}.`;
  } else if (dB === 0) {
    relation = `${a.name} هو ${descendantLabel(a, dA)} بالنسبة إلى ${b.name}.`;
  } else if (dA === 1 && dB === 1) {
    relation = `${a.name} و ${b.name} إخوة أو أخوات، ويجمعهما ${parentLabel(common)}: ${common.name}.`;
  } else if (dA === 1 && dB === 2) {
    const bParent = best.b.path[1];
    const side = bParent && Number(bParent.id) === Number(b.father_id) ? "عم" : "خال";
    const femaleSide = side === "عم" ? "عمة" : "خالة";
    relation = `${a.name} هو ${genderIsFemale(a) ? femaleSide : side} ${b.name}.`;
  } else if (dA === 2 && dB === 1) {
    const aParent = best.a.path[1];
    const side = aParent && Number(aParent.id) === Number(a.father_id) ? (genderIsFemale(b) ? "عمة" : "عم") : (genderIsFemale(b) ? "خالة" : "خال");
    relation = `${a.name} هو ${childLabel(a)} ${side} ${b.name}.`;
  } else if (dA === 2 && dB === 2) {
    relation = `${a.name} و ${b.name} أبناء عمومة/خؤولة، ويجمعهما ${ancestorLabel(common, 2)}: ${common.name}.`;
  } else {
    relation = `${a.name} و ${b.name} بينهما صلة قرابة عبر ${ancestorLabel(common, Math.max(dA, dB))} المشترك: ${common.name}.`;
  }

  return {
    ok:true,
    message:`${relation}\nمسار القرابة: ${personPathText(fullPath)}`,
    path: fullPath.map((p)=>({ id:p.id, name:p.name })),
    commonAncestor: { id: common.id, name: common.name },
  };
}

async function calculateKinshipByNames(personA, personB) {
  const { rows, byId } = await getPersonsForRelationship();
  const aMatch = matchPersonByFlexibleName(personA, rows, byId);
  const bMatch = matchPersonByFlexibleName(personB, rows, byId);
  if (aMatch.status !== "matched") {
    if (aMatch.status === "multiple") return { ok:false, message:`يوجد أكثر من شخص مطابق للاسم الأول. برجاء كتابة الاسم رباعي أو توضيح أكبر.\nالنتائج المحتملة: ${aMatch.matches.map(x=>`${x.name} (${x.lineage_label})`).join("، ")}` };
    return { ok:false, message:"لم يتم العثور على الشخص الأول داخل الشجرة. برجاء كتابة الاسم ثلاثي أو رباعي." };
  }
  if (bMatch.status !== "matched") {
    if (bMatch.status === "multiple") return { ok:false, message:`يوجد أكثر من شخص مطابق للاسم الثاني. برجاء كتابة الاسم رباعي أو توضيح أكبر.\nالنتائج المحتملة: ${bMatch.matches.map(x=>`${x.name} (${x.lineage_label})`).join("، ")}` };
    return { ok:false, message:"لم يتم العثور على الشخص الثاني داخل الشجرة. برجاء كتابة الاسم ثلاثي أو رباعي." };
  }
  return describeKinship(aMatch.matches[0], bMatch.matches[0], byId);
}



function removeArabicQuestionNoise(text) {
  return cleanText(String(text || "")
    .replace(/[؟?]/g, " ")
    .replace(/[،,؛;:]/g, " ")
    .replace(/\s+/g, " "), 500);
}

function stripAssistantNameNoise(text) {
  let value = removeArabicQuestionNoise(text);

  const prefixPatterns = [
    /^(?:ممكن\s+)?(?:تفاصيل\s+عن|معلومات\s+عن|بيانات\s+عن|نبذة\s+عن|نبذه\s+عن|سيرة\s+عن|السيرة\s+الذاتية\s+لـ?|السيرة\s+لـ?)\s+/i,
    /^(?:من\s+هو|من\s+هوا|من\s+هوه|من\s+هي|مين\s+هو|مين\s+هوا|مين\s+هوه|مين\s+هي|مين|منو|من\s+يكون|من\s+هو\s+الذي|من\s+هي\s+التي|من)\s+/i,
    /^(?:اعرفني\s+على|عرفني\s+على|عرّفني\s+على|اخبرني\s+عن|أخبرني\s+عن|قول\s+لي\s+عن|قولي\s+عن|كلمتك\s+عن|عايز\s+اعرف\s+عن|عايز\s+تفاصيل\s+عن|اريد\s+معرفة|أريد\s+معرفة|ابغى\s+اعرف\s+عن|وش\s+تعرف\s+عن|ما\s+تعرف\s+عن)\s+/i,
    /^(?:تفاصيل|سيرة|السيرة\s+الذاتية|نبذة|نبذه|معلومات|بيانات|موقع|مكان|فين|أين|اين|شاهد|اعرض|عرض)\s+/i,
    /^(?:عن|لـ|ل|هو|هوا|هوه|هي)\s+/i
  ];

  let changed = true;
  while (changed) {
    changed = false;
    for (const re of prefixPatterns) {
      const next = value.replace(re, "").trim();
      if (next !== value) { value = next; changed = true; }
    }
  }

  value = value
    .replace(/\s+(?:في\s+الشجرة|داخل\s+الشجرة|من\s+الشجرة|بالشجرة|على\s+الشجرة|السيرة\s+الذاتية|سيرته|سيرتها|نبذته|نبذتها|بياناته|بياناتها|تفاصيله|تفاصيلها|موقعه|موقعها)$/i, "")
    .replace(/^(?:عن|لـ|ل)\s+/i, "");

  return cleanText(value, 220);
}

function isLikelyPersonLookupQuestion(question) {
  const raw = removeArabicQuestionNoise(question);
  const n = normalizeArabicForMatch(raw);
  if (!n) return false;
  const triggers = [
    "من هو", "من هوا", "من هوه", "من هي", "مين", "منو", "من يكون", "من ",
    "اخبرني عن", "أخبرني عن", "قول لي عن", "قولي عن", "عرفني على", "اعرفني على",
    "تفاصيل", "تفاصيل عن", "سيرة", "السيرة الذاتية", "نبذة", "نبذه", "معلومات", "معلومات عن", "بيانات", "بيانات عن",
    "موقع", "مكان", "فين", "اين", "أين", "اعرض", "شاهد"
  ];
  if (triggers.some((t) => n.includes(normalizeArabicForMatch(t)))) return true;
  const stripped = stripAssistantNameNoise(raw);
  return isProbablyNameText(stripped);
}

function isProbablyNameText(text) {
  const parts = namePartsForMatch(text);
  if (parts.length < 2) return false;
  const n = normalizeArabicForMatch(text);
  const generalWords = ["كره", "كرة", "رياضه", "رياضة", "اخبار", "أخبار", "طقس", "سعر", "مباراه", "مباراة", "ما هي", "ما هو", "كيف", "لماذا", "ليه", "ايه معنى", "اشرح", "تعريف"];
  return !generalWords.some((w) => n.includes(normalizeArabicForMatch(w)));
}

function clarifyAssistantAnswer() {
  return { answer: "لم أفهم سؤالك بشكل كافٍ. وضّح المطلوب أكثر، أو اكتب اسم الشخص ثلاثي/رباعي، أو اكتب مثلًا: من هو فلان؟ أو ما صلة القرابة بين فلان وفلان؟" };
}


function arabicNumber(value) {
  return String(value).replace(/\d/g, (d) => "٠١٢٣٤٥٦٧٨٩"[Number(d)]);
}

function normalizeMonthQuery(value) {
  return normalizeArabicForMatch(String(value || "").replace(/شهر\s+/g, "").trim());
}

const HIJRI_MONTHS = [
  { n: 1, names: ["محرم", "محرم الحرام"] },
  { n: 2, names: ["صفر"] },
  { n: 3, names: ["ربيع الاول", "ربيع الأول", "ربيع اول"] },
  { n: 4, names: ["ربيع الثاني", "ربيع الاخر", "ربيع الآخر", "ربيع ثاني"] },
  { n: 5, names: ["جمادى الاولى", "جمادى الأولى", "جمادي الاولى", "جمادي الأولى"] },
  { n: 6, names: ["جمادى الاخرة", "جمادى الآخرة", "جمادى الثاني", "جمادي الاخرة", "جمادي الثاني"] },
  { n: 7, names: ["رجب"] },
  { n: 8, names: ["شعبان"] },
  { n: 9, names: ["رمضان"] },
  { n: 10, names: ["شوال"] },
  { n: 11, names: ["ذو القعدة", "ذو القعده", "ذو القعدة"] },
  { n: 12, names: ["ذو الحجة", "ذو الحجه"] },
];

const GREGORIAN_MONTHS = [
  { n: 0, names: ["يناير", "كانون الثاني", "january", "jan"] },
  { n: 1, names: ["فبراير", "شباط", "february", "feb"] },
  { n: 2, names: ["مارس", "آذار", "اذار", "march", "mar"] },
  { n: 3, names: ["ابريل", "أبريل", "نيسان", "april", "apr"] },
  { n: 4, names: ["مايو", "ايار", "أيار", "may"] },
  { n: 5, names: ["يونيو", "حزيران", "june", "jun"] },
  { n: 6, names: ["يوليو", "تموز", "july", "jul"] },
  { n: 7, names: ["اغسطس", "أغسطس", "آب", "اب", "august", "aug"] },
  { n: 8, names: ["سبتمبر", "ايلول", "أيلول", "september", "sep"] },
  { n: 9, names: ["اكتوبر", "أكتوبر", "تشرين الاول", "تشرين الأول", "october", "oct"] },
  { n: 10, names: ["نوفمبر", "تشرين الثاني", "november", "nov"] },
  { n: 11, names: ["ديسمبر", "كانون الاول", "كانون الأول", "december", "dec"] },
];

function getNowInRiyadh() {
  return new Date();
}

function formatGregorianDateArabic(date = new Date()) {
  return new Intl.DateTimeFormat("ar-SA-u-ca-gregory", {
    timeZone: "Asia/Riyadh",
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric"
  }).format(date);
}

function formatTimeArabic(date = new Date()) {
  return new Intl.DateTimeFormat("ar-SA", {
    timeZone: "Asia/Riyadh",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  }).format(date);
}

function formatHijriDateArabic(date = new Date()) {
  try {
    return new Intl.DateTimeFormat("ar-SA-u-ca-islamic-umalqura", {
      timeZone: "Asia/Riyadh",
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric"
    }).format(date);
  } catch (_) {
    return "غير متاح بدقة على هذا الخادم";
  }
}

function getHijriMonthNumber(date) {
  try {
    const parts = new Intl.DateTimeFormat("en-u-ca-islamic-umalqura", {
      timeZone: "Asia/Riyadh",
      month: "numeric"
    }).formatToParts(date);
    const month = Number(parts.find((p) => p.type === "month")?.value || 0);
    return month || null;
  } catch (_) {
    return null;
  }
}

function findNextHijriMonthStart(targetMonthNumber) {
  const now = new Date();
  let previous = getHijriMonthNumber(now);
  for (let i = 0; i <= 370; i++) {
    const d = new Date(now.getTime() + i * 24 * 60 * 60 * 1000);
    const m = getHijriMonthNumber(d);
    if (m === targetMonthNumber && (i === 0 || previous !== targetMonthNumber)) return { date: d, days: i };
    previous = m;
  }
  return null;
}

function findNextGregorianMonthStart(targetMonthIndex) {
  const now = new Date();
  const riyadhParts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Riyadh",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(now).reduce((acc, p) => (acc[p.type] = p.value, acc), {});
  const year = Number(riyadhParts.year);
  const currentMonth = Number(riyadhParts.month) - 1;
  const currentDay = Number(riyadhParts.day);
  let targetYear = year;
  if (targetMonthIndex < currentMonth || (targetMonthIndex === currentMonth && currentDay > 1)) targetYear += 1;
  const start = new Date(Date.UTC(targetYear, targetMonthIndex, 1, 0, 0, 0));
  const todayStart = new Date(Date.UTC(year, currentMonth, currentDay, 0, 0, 0));
  const days = Math.max(0, Math.ceil((start - todayStart) / (24 * 60 * 60 * 1000)));
  return { date: start, days };
}

function detectMonthCountdown(question) {
  const nq = normalizeArabicForMatch(question);
  if (!(nq.includes("كم باقي") || nq.includes("كم متبقي") || nq.includes("متى") || nq.includes("موعد") || nq.includes("باقي على") || nq.includes("باقي ل"))) return null;

  for (const item of HIJRI_MONTHS) {
    if (item.names.some((name) => nq.includes(normalizeMonthQuery(name)))) {
      const next = findNextHijriMonthStart(item.n);
      if (!next) return { answer: "لا أستطيع حساب هذا الشهر الهجري بدقة على الخادم الحالي." };
      return {
        answer: `باقي على ${item.names[0]} تقريبًا ${arabicNumber(next.days)} يوم.\nالتاريخ المتوقع لبداية الشهر: ${formatGregorianDateArabic(next.date)}.\nملاحظة: الأشهر الهجرية تعتمد على الرؤية الشرعية، لذلك قد يختلف التاريخ يومًا بالزيادة أو النقصان.`
      };
    }
  }
  for (const item of GREGORIAN_MONTHS) {
    if (item.names.some((name) => nq.includes(normalizeMonthQuery(name)))) {
      const next = findNextGregorianMonthStart(item.n);
      return {
        answer: `باقي على شهر ${item.names[0]} ${arabicNumber(next.days)} يوم تقريبًا.\nبدايته تكون في ${formatGregorianDateArabic(next.date)}.`
      };
    }
  }
  return null;
}

function answerGreetingQuestion(question) {
  const nq = normalizeArabicForMatch(question);
  const greetings = ["هلا", "هلا والله", "مرحبا", "السلام عليكم", "كيف الحال", "وش اخبارك", "وش علومك", "صباح الخير", "مساء الخير", "اهلا", "أهلا"];
  if (!greetings.some((x) => nq.includes(normalizeArabicForMatch(x)))) return null;
  if (nq.includes("السلام عليكم")) return { answer: "وعليكم السلام ورحمة الله وبركاته، حيّاك الله. أبشر، اسألني عن أي فرد في الشجرة، صلة قرابة، تاريخ العائلة، أو طريقة استخدام الموقع." };
  if (nq.includes("صباح")) return { answer: "صباح النور والسرور، حيّاك الله. وش تبي تعرف عن العائلة أو الموقع؟" };
  if (nq.includes("مساء")) return { answer: "مساء الخير، يا هلا والله. اسألني عن أي شخص في الشجرة أو صلة قرابة بين اسمين." };
  return { answer: "يا هلا والله، أبشر. أنا مساعد الموقع، أقدر أساعدك في الشجرة، تاريخ العائلة، صلة القرابة، تتبع الطلبات، وأي سؤال واضح تكتبه لي." };
}

function answerDateTimeQuestion(question) {
  const nq = normalizeArabicForMatch(question);
  const wantsDate = ["تاريخ اليوم", "اي تاريخ اليوم", "كم التاريخ", "النهارده كام", "اليوم كام", "تاريخ هجري", "التاريخ الهجري", "التاريخ الميلادي"].some((x) => nq.includes(normalizeArabicForMatch(x)));
  const wantsTime = ["كم الساعة", "كم الساعه", "الساعة كم", "الساعه كم", "الوقت الان", "الوقت الآن", "اي وقت", "الوقت كام"].some((x) => nq.includes(normalizeArabicForMatch(x)));
  const monthCountdown = detectMonthCountdown(question);
  if (monthCountdown) return monthCountdown;
  if (!wantsDate && !wantsTime) return null;
  const now = new Date();
  const parts = [];
  if (wantsTime) parts.push(`الوقت الآن حسب توقيت السعودية: ${formatTimeArabic(now)}.`);
  if (wantsDate) {
    parts.push(`التاريخ الميلادي: ${formatGregorianDateArabic(now)}.`);
    parts.push(`التاريخ الهجري: ${formatHijriDateArabic(now)}.`);
  }
  return { answer: parts.join("\n") };
}

function calculateAgeFromDate(dateValue) {
  if (!dateValue) return null;
  const raw = String(dateValue).trim();
  const m = raw.match(/(\d{4})[-\/](\d{1,2})[-\/](\d{1,2})/);
  if (!m) return null;
  const y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
  if (!y || !mo || !d) return null;
  const birth = new Date(Date.UTC(y, mo - 1, d));
  const now = new Date();
  let age = now.getUTCFullYear() - birth.getUTCFullYear();
  const thisMonth = now.getUTCMonth() + 1;
  const thisDay = now.getUTCDate();
  if (thisMonth < mo || (thisMonth === mo && thisDay < d)) age -= 1;
  return age >= 0 && age < 140 ? age : null;
}

function extractNameAfterPatterns(question, patterns) {
  let q = removeArabicQuestionNoise(question);
  for (const re of patterns) {
    const m = q.match(re);
    if (m && m[1]) return stripAssistantNameNoise(m[1]);
  }
  return stripAssistantNameNoise(q);
}

function isAgeQuestion(question) {
  const nq = normalizeArabicForMatch(question);
  return ["كم عمر", "عمر", "سن", "مواليد", "متى ولد", "تاريخ ميلاد"].some((x) => nq.includes(normalizeArabicForMatch(x)));
}

function isChildrenCountQuestion(question) {
  const nq = normalizeArabicForMatch(question);
  return (["كم ابناء", "كم أبناء", "كم ولد", "كم بنت", "عنده كم", "عندها كم", "عدد ابناء", "عدد أبناء", "ابناء", "أبناء", "اولاد", "أولاد", "بنات"].some((x) => nq.includes(normalizeArabicForMatch(x))) && !nq.includes("احصائيات"));
}

async function answerPersonAgeQuestion(question) {
  const { rows, byId } = await getPersonsForRelationship();
  const name = extractNameAfterPatterns(question, [
    /(?:كم\s+عمر|عمر|سن)\s+(.+)$/i,
    /(?:مواليد|متى\s+ولد|تاريخ\s+ميلاد)\s+(.+)$/i,
    /(.+?)\s+(?:كم\s+عمره|كم\s+عمرها|عمره\s+كم|عمرها\s+كم|مواليد\s+كم)$/i
  ]);
  const match = matchPersonByFlexibleName(name, rows, byId);
  if (match.status === "matched") {
    const person = match.matches[0];
    if (!person.birth_date) return { answer: `وجدت ${person.name}، لكن تاريخ الميلاد غير مسجل، لذلك لا أستطيع حساب العمر.`, actions: [{ label: "عرض موقعه في الشجرة", url: `/?focus=${person.id}` }] };
    const age = calculateAgeFromDate(person.birth_date);
    if (age === null) return { answer: `تاريخ ميلاد ${person.name} مسجل بالشكل التالي: ${person.birth_date}، لكن لا يمكن حساب العمر منه بدقة.` };
    return { answer: `${person.name} عمره تقريبًا ${arabicNumber(age)} سنة.\nتاريخ الميلاد المسجل: ${person.birth_date}.`, actions: [{ label: "عرض موقعه في الشجرة", url: `/?focus=${person.id}` }] };
  }
  if (match.status === "multiple") return { answer: `وجدت أكثر من شخص بهذا الاسم. اكتب الاسم رباعي لتحديد الشخص بدقة:\n${match.matches.map((x,i)=>`${i+1}- ${x.name} (${x.lineage_label})`).join("\n")}` };
  return null;
}

async function answerChildrenCountQuestion(question) {
  const { rows, byId } = await getPersonsForRelationship();
  const name = extractNameAfterPatterns(question, [
    /(?:كم\s+ابناء|كم\s+أبناء|كم\s+اولاد|كم\s+أولاد|كم\s+ولد|كم\s+بنت|عدد\s+ابناء|عدد\s+أبناء|ابناء|أبناء|اولاد|أولاد|بنات)\s+(.+)$/i,
    /(.+?)\s+(?:عنده|عندها)\s+كم\s+(?:ولد|بنت|ابن|ابنة|أبناء|ابناء|أولاد|اولاد)$/i,
    /(.+?)\s+(?:كم\s+عنده|كم\s+عندها)\s+(?:ولد|بنت|ابن|ابنة|أبناء|ابناء|أولاد|اولاد)$/i,
    /(.+?)\s+(?:عنده|عندها)\s+(?:اولاد|أولاد|ابناء|أبناء|بنات)$/i
  ]);
  const match = matchPersonByFlexibleName(name, rows, byId);
  if (match.status === "matched") {
    const person = match.matches[0];
    const children = rows.filter((x)=>Number(x.father_id)===Number(person.id)||Number(x.mother_id)===Number(person.id));
    const sons = children.filter((c)=>genderIsMale(c));
    const daughters = children.filter((c)=>genderIsFemale(c));
    const unknown = children.length - sons.length - daughters.length;
    const lines = [`${person.name} لديه/لديها ${arabicNumber(children.length)} من الأبناء المسجلين في الشجرة.`];
    lines.push(`الأولاد: ${arabicNumber(sons.length)}.`);
    lines.push(`البنات: ${arabicNumber(daughters.length)}.`);
    if (unknown > 0) lines.push(`غير محدد النوع: ${arabicNumber(unknown)}.`);
    if (children.length) lines.push(`الأسماء: ${children.map(c=>c.name).join("، ")}.`);
    return { answer: lines.join("\n"), actions: [{ label: "عرض موقعه في الشجرة", url: `/?focus=${person.id}` }] };
  }
  if (match.status === "multiple") return { answer: `وجدت أكثر من شخص بهذا الاسم. اكتب الاسم رباعي لتحديد الشخص بدقة:\n${match.matches.map((x,i)=>`${i+1}- ${x.name} (${x.lineage_label})`).join("\n")}` };
  return null;
}

function normalizeDigitsToLatin(value) {
  const map = { "٠":"0","١":"1","٢":"2","٣":"3","٤":"4","٥":"5","٦":"6","٧":"7","٨":"8","٩":"9","۰":"0","۱":"1","۲":"2","۳":"3","۴":"4","۵":"5","۶":"6","۷":"7","۸":"8","۹":"9" };
  return String(value || "").replace(/[٠-٩۰-۹]/g, (d) => map[d] || d);
}

function answerSimpleMathQuestion(question) {
  let q = normalizeDigitsToLatin(normalizeArabicForMatch(question || ""));
  const original = q;
  q = q.replace(/اضربلي|اضرب|احسبلي|احسب|بكام|يساوي|يساوى|كام|كم|ايش|وش|يعني/g, " ").replace(/\s+/g, " ").trim();
  const mult = q.match(/(-?\d+(?:\.\d+)?)\s*(?:في|x|×|\*)\s*(-?\d+(?:\.\d+)?)/i) || original.match(/(-?\d+(?:\.\d+)?)\s*(?:في|x|×|\*)\s*(-?\d+(?:\.\d+)?)/i);
  if (mult) {
    const a = Number(mult[1]);
    const b = Number(mult[2]);
    if (Number.isFinite(a) && Number.isFinite(b)) return { answer: `${arabicNumber(a)} × ${arabicNumber(b)} = ${arabicNumber(a * b)}.` };
  }
  const plus = q.match(/(-?\d+(?:\.\d+)?)\s*(?:\+|زائد|جمع|مع)\s*(-?\d+(?:\.\d+)?)/i);
  if (plus) {
    const a = Number(plus[1]);
    const b = Number(plus[2]);
    if (Number.isFinite(a) && Number.isFinite(b)) return { answer: `${arabicNumber(a)} + ${arabicNumber(b)} = ${arabicNumber(a + b)}.` };
  }
  const minus = q.match(/(-?\d+(?:\.\d+)?)\s*(?:\-|ناقص|طرح)\s*(-?\d+(?:\.\d+)?)/i);
  if (minus) {
    const a = Number(minus[1]);
    const b = Number(minus[2]);
    if (Number.isFinite(a) && Number.isFinite(b)) return { answer: `${arabicNumber(a)} - ${arabicNumber(b)} = ${arabicNumber(a - b)}.` };
  }
  const div = q.match(/(-?\d+(?:\.\d+)?)\s*(?:\/|÷|على|قسمه|قسمة)\s*(-?\d+(?:\.\d+)?)/i);
  if (div) {
    const a = Number(div[1]);
    const b = Number(div[2]);
    if (Number.isFinite(a) && Number.isFinite(b)) {
      if (b === 0) return { answer: "لا يمكن القسمة على صفر." };
      return { answer: `${arabicNumber(a)} ÷ ${arabicNumber(b)} = ${arabicNumber(Number((a / b).toFixed(4)))}.` };
    }
  }
  return null;
}

const ASSISTANT_APPROX_WEATHER = {
  "الرياض": [20, 23, 27, 32, 38, 42, 43, 43, 40, 34, 27, 21],
  "جدة": [27, 28, 30, 32, 35, 37, 38, 38, 37, 35, 32, 29],
  "مكة": [29, 31, 34, 38, 42, 44, 44, 44, 42, 38, 34, 30],
  "المدينة": [22, 25, 29, 34, 39, 43, 43, 43, 40, 34, 28, 23],
  "الدمام": [22, 24, 28, 33, 39, 43, 44, 43, 40, 35, 29, 24],
  "الطائف": [19, 21, 24, 27, 31, 34, 34, 34, 32, 28, 24, 20],
  "القاهرة": [19, 21, 24, 29, 33, 35, 36, 35, 33, 29, 25, 20],
  "الإسكندرية": [18, 19, 21, 24, 28, 31, 32, 32, 30, 27, 23, 19]
};

function answerApproxWeatherQuestion(question) {
  const q = normalizeArabicForMatch(question || "");
  const hasWeather = [
    "كم درجة الحرارة", "درجة الحرارة", "درجه الحراره", "حرارة اليوم", "الجو اليوم", "الطقس اليوم", "كم الحراره", "كم الحرارة", "وش الجو", "ايش الجو", "الجو كيف", "كيف الجو", "حرارة الرياض", "درجة الجو", "الحرارة اليوم"
  ].some((p)=>q.includes(normalizeArabicForMatch(p)));
  if (!hasWeather) return null;

  const cityProfiles = [
    { city:"الرياض", aliases:["الرياض", "رياض"] },
    { city:"جدة", aliases:["جدة", "جده"] },
    { city:"مكة", aliases:["مكة", "مكه", "مكة المكرمة", "مكه المكرمه"] },
    { city:"المدينة", aliases:["المدينة", "المدينه", "المدينة المنورة", "المدينه المنوره"] },
    { city:"بريدة", aliases:["بريدة", "بريده"] },
    { city:"القصيم", aliases:["القصيم", "قصيم", "عنيزة", "عنيزه", "الرس", "المذنب"] },
    { city:"حاير", aliases:["حاير", "الحائر", "الحاير"] },
    { city:"الخرج", aliases:["الخرج", "خرج"] },
    { city:"الدمام", aliases:["الدمام", "الخبر", "الشرقية", "الشرقيه", "الظهران"] },
    { city:"الطائف", aliases:["الطائف", "طايف"] },
    { city:"القاهرة", aliases:["القاهرة", "القاهره", "مصر", "مصر الجديدة"] },
    { city:"الإسكندرية", aliases:["الإسكندرية", "الاسكندرية", "اسكندرية", "اسكندريه"] }
  ];

  const averages = {
    "الرياض": [20, 23, 27, 32, 38, 42, 43, 43, 40, 34, 27, 21],
    "جدة": [27, 28, 30, 32, 35, 37, 38, 38, 37, 35, 32, 29],
    "مكة": [29, 31, 34, 38, 42, 44, 44, 44, 42, 38, 34, 30],
    "المدينة": [22, 25, 29, 34, 39, 43, 43, 43, 40, 34, 28, 23],
    "بريدة": [17, 20, 25, 31, 37, 42, 43, 42, 39, 32, 24, 18],
    "القصيم": [17, 20, 25, 31, 37, 42, 43, 42, 39, 32, 24, 18],
    "حاير": [20, 23, 27, 33, 39, 43, 44, 43, 40, 34, 27, 21],
    "الخرج": [20, 23, 28, 34, 40, 44, 45, 44, 41, 35, 27, 21],
    "الدمام": [22, 24, 28, 33, 39, 43, 44, 43, 40, 35, 29, 24],
    "الطائف": [19, 21, 24, 27, 31, 34, 34, 34, 32, 28, 24, 20],
    "القاهرة": [19, 21, 24, 29, 33, 35, 36, 35, 33, 29, 25, 20],
    "الإسكندرية": [18, 19, 21, 24, 28, 31, 32, 32, 30, 27, 23, 19]
  };

  let city = "الرياض";
  for (const item of cityProfiles) {
    if (item.aliases.some(alias => q.includes(normalizeArabicForMatch(alias)))) {
      city = item.city;
      break;
    }
  }

  const avg = (averages[city] || averages["الرياض"])[new Date().getMonth()];
  return { answer: `درجة الحرارة في ${city} اليوم تقريبًا ${arabicNumber(avg)}°C.` };
}



function answerWebsiteFAQ(question) {
  const q = cleanText(question || "", 1200);
  const nq = normalizeArabicForMatch(q);
  if (!nq) return null;
  const hasAny = (...words) => words.some((w) => nq.includes(normalizeArabicForMatch(w)));

  if (hasAny("الية عمل الموقع", "آلية عمل الموقع", "ازاي الموقع شغال", "كيف يعمل الموقع", "طريقة عمل الموقع", "شرح الموقع", "الموقع بيشتغل ازاي", "استخدم الموقع ازاي", "كيفية استخدام الموقع", "ايه فكره الموقع", "فكرة الموقع")) {
    return {
      answer: "آلية عمل الموقع باختصار:\n1- يعرض شجرة العائلة التفاعلية حتى يستطيع الزائر تصفح أفراد العائلة ومعرفة أماكنهم داخل الشجرة.\n2- يمكن البحث عن شخص بالاسم ثم الانتقال مباشرة إلى موقعه في الشجرة.\n3- يمكن إرسال طلب إضافة بيانات فرد جديد من صفحة إضافة بياناتك، ولا يظهر الطلب في الشجرة إلا بعد مراجعة الإدارة واعتماده.\n4- بعد إرسال الطلب يحصل المستخدم على رقم مرجعي لتتبع حالة الطلب.\n5- توجد صفحات للأخبار والمناسبات والسير الذاتية ورسائل الدعم وصلة القرابة.\n6- لوحة الإدارة مخصصة للمسؤولين لاعتماد الطلبات وتحديث البيانات والمحتوى.",
      actions: [
        { label: "فتح الشجرة", url: "/" },
        { label: "إضافة بياناتك", url: "/submit-person" },
        { label: "صلة القرابة", url: "/kinship" }
      ]
    };
  }

  if (hasAny("من يدير الموقع", "مين يدير الموقع", "مين مدير الموقع", "من مدير الموقع", "ادارة الموقع", "إدارة الموقع", "المسؤول عن الموقع", "المسؤولين عن الموقع", "من المسؤول", "مين المسؤول")) {
    return {
      answer: "يدير الموقع مسؤولو العائلة المصرّح لهم من خلال لوحة إدارة خاصة. الإدارة مسؤولة عن مراجعة طلبات إضافة الأفراد، تحديث بيانات الشجرة، نشر الأخبار والمناسبات، وإدارة السير الذاتية ورسائل الدعم.\nللحفاظ على الخصوصية لا يتم عرض بيانات حسابات الإدارة أو بياناتهم الخاصة للعامة.",
      actions: [
        { label: "التواصل مع الإدارة", url: "/support" },
        { label: "إرسال بيانات فرد", url: "/submit-person" }
      ]
    };
  }

  if (hasAny("كيف نتواصل", "كيف اتواصل", "ازاي اتواصل", "التواصل مع الادارة", "التواصل مع الإدارة", "كلم الادارة", "اكلم الادارة", "راسل الادارة", "رسائل الدعم", "الدعم", "تواصل معنا", "رقم الادارة", "رقم الإدارة", "ايميل الادارة", "بريد الادارة")) {
    return {
      answer: "يمكنك التواصل مع إدارة الموقع من خلال صفحة رسائل الدعم. اكتب اسمك ووسيلة التواصل ورسالتك، وستصل للإدارة داخل لوحة التحكم لمراجعتها والرد عليك حسب المتاح.\nلا أنصح بكتابة بيانات حساسة داخل الرسالة إلا عند الضرورة.",
      link: "/support",
      linkLabel: "فتح صفحة الدعم",
      actions: [
        { label: "التواصل مع الإدارة", url: "/support" }
      ]
    };
  }

  if (hasAny("هل بياناتي تظهر", "متى تظهر بياناتي", "امتى يظهر اسمي", "ليش اسمي ما ظهر", "لماذا اسمي لا يظهر", "لم يظهر اسمي", "طلبي لم يظهر", "بياناتي لم تظهر", "مراجعة الطلب")) {
    return {
      answer: "بياناتك لا تظهر مباشرة بعد الإرسال. الطلب يذهب أولًا إلى إدارة الموقع للمراجعة. إذا تمت الموافقة، يتم إنشاء الفرد داخل الشجرة ويصبح ظاهرًا. إذا تم الرفض، تظهر لك حالة الرفض وسبب الرفض عند تتبع الطلب بالرقم المرجعي.",
      actions: [
        { label: "تتبع الطلب", url: "/submit-person#track-request" },
        { label: "إضافة بياناتك", url: "/submit-person" }
      ]
    };
  }

  if (hasAny("الرقم المرجعي", "رمز التتبع", "كود التتبع", "رقم الطلب", "انسخ الرقم", "نسيت الرقم", "كيف اتابع", "ازاي اتابع", "حالة الطلب")) {
    return {
      answer: "بعد إرسال طلب إضافة البيانات يظهر لك رقم مرجعي خاص بطلبك. احتفظ به واستخدمه في قسم تتبع الطلب لمعرفة هل الطلب قيد المراجعة أو تمت الموافقة عليه أو تم رفضه مع سبب الرفض. إذا تمت الموافقة يظهر لك زر للانتقال إلى موقعك في الشجرة.",
      actions: [
        { label: "تتبع الطلب", url: "/submit-person#track-request" }
      ]
    };
  }

  if (hasAny("كيف اضيف بياناتي", "كيف أضيف بياناتي", "ازاي اضيف بياناتي", "اضافة بياناتي", "إضافة بياناتي", "اضيف نفسي", "أضيف نفسي", "اسجل في الشجرة", "انضم للشجرة", "اضافة فرد")) {
    return {
      answer: "لإضافة بياناتك: افتح صفحة إضافة بياناتك، املأ البيانات المطلوبة مثل الاسم، الأب، الأم، تاريخ الميلاد، الصورة، العمل، المستوى التعليمي، العنوان، الزوج/الزوجة والأبناء إن وجدوا، ثم اضغط إرسال للمراجعة. بعد الإرسال سيظهر لك رقم مرجعي لتتبع الطلب.",
      actions: [
        { label: "إضافة بياناتك", url: "/submit-person" },
        { label: "تتبع الطلب", url: "/submit-person#track-request" }
      ]
    };
  }

  if (hasAny("خصوصية", "الخصوصية", "بيانات خاصة", "رقم الجوال", "رقم الهاتف", "الايميل", "الإيميل", "العنوان", "هل يظهر جوالي", "هل يظهر رقمي", "هل يظهر عنواني")) {
    return {
      answer: "الموقع يحافظ على خصوصية البيانات الحساسة. بيانات مثل رقم الجوال والبريد الإلكتروني والعنوان مخصصة للإدارة فقط ولا تظهر للعامة في صفحات الموقع أو الشجرة، إلا إذا قررت الإدارة تغيير ذلك صراحة.",
      actions: [
        { label: "التواصل مع الإدارة", url: "/support" }
      ]
    };
  }

  if (hasAny("صلة القرابة", "صله القرابه", "هذه قريبي", "قريبي", "اعرف القرابة", "معرفة القرابة")) {
    return {
      answer: "يمكنك معرفة صلة القرابة بكتابة السؤال مباشرة مثل: ما صلة القرابة بين فلان وفلان؟ وسأحاول حسابها من بيانات الشجرة. ويمكنك أيضًا استخدام صفحة صلة القرابة وكتابة الاسمين ثلاثي أو رباعي للحصول على نتيجة أوضح.",
      actions: [
        { label: "فتح صفحة صلة القرابة", url: "/kinship" }
      ]
    };
  }

  if (hasAny("السيرة الذاتية", "السير الذاتية", "نبذة", "نبذه", "سيرة", "سيرته", "سيرتها")) {
    return {
      answer: "صفحة السير الذاتية تعرض نبذات وتفاصيل مميزة عن أفراد العائلة المسجلين. يمكنك سؤالي عن شخص باسمه، وإذا كان له بيانات أو سيرة ذاتية سأعرض لك ملخصًا وروابط لفتح سيرته أو موقعه في الشجرة.",
      actions: [
        { label: "فتح السير الذاتية", url: "/honor" }
      ]
    };
  }

  if (hasAny("الاخبار", "الأخبار", "المناسبات", "مناسبة", "خبر", "اخر اخبار العائلة", "آخر أخبار العائلة")) {
    return {
      answer: "صفحة الأخبار والمناسبات تعرض ما تنشره إدارة الموقع من أخبار العائلة والمناسبات. يمكنك أن تسألني عن آخر خبر منشور، أو تفتح صفحة الأخبار للاطلاع على كل الأخبار المتاحة.",
      actions: [
        { label: "فتح الأخبار والمناسبات", url: "/news" }
      ]
    };
  }

  if (hasAny("مشجر", "ملف الشجرة", "pdf", "بي دي اف", "تحميل الشجرة", "عرض الشجرة")) {
    return {
      answer: "يمكنك تصفح الشجرة التفاعلية من الصفحة الرئيسية. وإذا كانت إدارة الموقع أضافت ملف مشجر أو PDF، يمكنك فتح صفحة مشجرة العائلة للاطلاع عليه أو تحميله حسب المتاح.",
      actions: [
        { label: "الشجرة التفاعلية", url: "/" },
        { label: "مشجرة العائلة", url: "/tree-pdf" }
      ]
    };
  }

  if (hasAny("تسجيل الدخول", "دخول الادارة", "دخول الإدارة", "لوحة الادارة", "لوحة الإدارة", "انا ادمن", "أنا أدمن")) {
    return {
      answer: "تسجيل الدخول مخصص للمسؤولين والمصرح لهم فقط. إذا كنت من الإدارة يمكنك الدخول من زر تسجيل الدخول. أما الزوار فيمكنهم استخدام صفحات إضافة البيانات وتتبع الطلب والتواصل مع الإدارة دون دخول.",
      actions: [
        { label: "تسجيل الدخول", url: "/admin/login" },
        { label: "إضافة بياناتك", url: "/submit-person" }
      ]
    };
  }

  return null;
}



function stripHtmlForAssistant(value, max = 1400) {
  return cleanText(String(value || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">"), max);
}

function isFamilyHistoryQuestion(question) {
  const nq = normalizeArabicForMatch(question);
  const phrases = [
    "تاريخ العائلة", "تاريخ العائله", "تاريخ الاسرة", "تاريخ الأسرة", "قصة العائلة", "قصة العائله", "قصة الاسرة", "قصة الأسرة",
    "نبذة العائلة", "نبذه العائله", "نبذة عن العائلة", "نبذه عن العائله", "عن العائلة", "عن العائله",
    "المحطات الزمنية", "المحطات الزمنيه", "الخط الزمني", "محطات العائلة", "محطات العائله",
    "احكيلي تاريخ", "احكي لي تاريخ", "احكي عن تاريخ", "عرفني بتاريخ", "ملخص تاريخ العائلة", "لمحة تاريخية"
  ].map(normalizeArabicForMatch);
  return phrases.some((x) => nq.includes(x));
}

async function getFamilyHistoryAssistantAnswer() {
  const page = await get(`SELECT title, subtitle, content FROM site_pages WHERE slug='about'`).catch(() => null);
  const timeline = await all(`SELECT title, description, date FROM timeline_events WHERE COALESCE(visible, 1)=1 ORDER BY "order" ASC, id ASC`).catch(() => []);

  const title = cleanText(page?.title || "تاريخ العائلة", 120);
  const subtitle = cleanText(page?.subtitle || "", 180);
  const content = stripHtmlForAssistant(page?.content || "", 1200);

  const lines = [];
  lines.push(`هذا ملخص ${title} كما هو مسجل في صفحة النبذة داخل الموقع.`);
  if (subtitle) lines.push(`\n${subtitle}`);
  if (content) lines.push(`\n${content}`);
  else lines.push("\nلم يتم إضافة نص تفصيلي في صفحة النبذة بعد، لذلك أعرض لك المحطات الزمنية المتاحة إن وجدت.");

  if (timeline.length) {
    lines.push("\nأبرز المحطات الزمنية:");
    timeline.slice(0, 10).forEach((item, index) => {
      const date = cleanText(item.date || "", 80);
      const itemTitle = cleanText(item.title || "محطة زمنية", 120);
      const desc = stripHtmlForAssistant(item.description || "", 220);
      lines.push(`${index + 1}. ${date ? date + " - " : ""}${itemTitle}${desc ? `: ${desc}` : ""}`);
    });
    if (timeline.length > 10) lines.push(`\nوهناك ${timeline.length - 10} محطة أخرى يمكنك الاطلاع عليها من صفحة النبذة.`);
  } else {
    lines.push("\nلا توجد محطات زمنية منشورة حاليًا في صفحة النبذة.");
  }

  return {
    answer: lines.join("\n"),
    actions: [
      { label: "فتح صفحة النبذة", url: "/about" },
      { label: "عرض الشجرة", url: "/" }
    ]
  };
}

function cleanKinshipNamePart(value) {
  return cleanText(String(value || "")
    .replace(/^(?:من|عن|اسم|الاسم|الشخص|هو|هوا|هوه|هي|الأول|الاول|الثاني|التاني)\s+/i, "")
    .replace(/\s+(?:من\s+العائلة|في\s+الشجرة|داخل\s+الشجرة|بالشجرة)$/i, "")
    .trim(), 220);
}

function extractKinshipNamesFromQuestion(question) {
  let q = removeArabicQuestionNoise(question);
  q = q
    .replace(/إيه/g, "ايه")
    .replace(/أيه/g, "ايه")
    .replace(/اي\s+/g, "ايه ")
    .replace(/ما\s+هي\s+/g, "")
    .replace(/ما\s+هو\s+/g, "")
    .replace(/ما\s+/g, "")
    .replace(/صلة\s+القرابة/g, "صلة القرابة")
    .replace(/صله\s+القرابه/g, "صلة القرابة")
    .replace(/صلة\s+القربى/g, "صلة القرابة")
    .replace(/قرابيه|قرابة|قرايب|قرايبين/g, "قرابة");

  const patterns = [
    /(?:صلة\s+القرابة|صلة|قرابة)\s+(?:بين\s+)?(.+?)\s+(?:و|وبين|مع)\s+(.+)$/i,
    /(?:ايه|ما)\s+(?:صلة\s+)?(?:قرابة|صلة)\s+(.+?)\s+(?:و|وبين|مع)\s+(.+)$/i,
    /(?:بين\s+)?(.+?)\s+(?:و|وبين|مع)\s+(.+?)\s+(?:ايه|ما)\s*(?:صلة|قرابة|يقربوا|يقربو|يقربان)?$/i,
    /(.+?)\s+(?:يقرب|تقرب|قريب|قريبة|قريبي)\s+(?:ايه\s+)?(?:من|لـ|ل)?\s+(.+)$/i,
    /(.+?)\s+(?:ايه|ما)\s+(?:يقرب|تقرب|صلة|قرابة)\s+(?:من|لـ|ل)?\s+(.+)$/i,
    /(.+?)\s+(?:ابن\s+مين|ابن\s+من|قريب\s+من)\s+(.+)$/i
  ];

  for (const re of patterns) {
    const m = q.match(re);
    if (m && m[1] && m[2]) {
      const a = cleanKinshipNamePart(m[1]);
      const b = cleanKinshipNamePart(m[2]);
      if (namePartsForMatch(a).length >= 1 && namePartsForMatch(b).length >= 1) return { a, b };
    }
  }
  return null;
}

async function buildPersonAssistantAnswer(person, rows, byId) {
  const father = person.father_id ? byId.get(Number(person.father_id)) : null;
  const mother = person.mother_id ? byId.get(Number(person.mother_id)) : null;
  const children = rows.filter((x)=>Number(x.father_id)===Number(person.id)||Number(x.mother_id)===Number(person.id));
  const spouses = await all(`SELECT spouse_name FROM person_spouses WHERE person_id = ? ORDER BY ord ASC, id ASC`, [person.id]).catch(()=>[]);
  const honor = await get(`SELECT id, field, bio, achievement FROM honor_items WHERE person_id = ? ORDER BY ord ASC, id ASC LIMIT 1`, [person.id]).catch(()=>null);

  const lines = [`وجدت الشخص: ${person.name}`];
  if (father) lines.push(`الأب: ${father.name}`);
  if (mother) lines.push(`الأم: ${mother.name}`);
  if (person.birth_date) lines.push(`تاريخ الميلاد: ${person.birth_date}`);
  if (person.death_date) lines.push(`تاريخ الوفاة: ${person.death_date}`);
  if (person.birth_place) lines.push(`مكان الميلاد: ${person.birth_place}`);
  if (person.job) lines.push(`العمل: ${person.job}`);
  if (person.education_level) lines.push(`المستوى التعليمي: ${person.education_level}`);
  if (spouses.length) lines.push(`الزوج/الزوجة: ${spouses.map(s=>s.spouse_name).filter(Boolean).join("، ")}`);
  lines.push(`عدد الأبناء المسجلين: ${children.length}`);
  if (children.length) lines.push(`من الأبناء المسجلين: ${children.slice(0, 6).map(c=>c.name).join("، ")}${children.length > 6 ? "..." : ""}`);
  const bio = honor?.bio || person.short_bio || person.notes;
  if (bio) lines.push(`نبذة: ${cleanText(bio, 320)}`);
  if (honor?.achievement) lines.push(`إنجاز/تفاصيل: ${cleanText(honor.achievement, 220)}`);

  return {
    answer: lines.join("\n"),
    link: `/?focus=${person.id}`,
    linkLabel: "عرض موقعه في الشجرة",
    actions: [
      { label: "عرض موقعه في الشجرة", url: `/?focus=${person.id}` },
      { label: "فتح سيرته الذاتية", url: `/honor?personId=${encodeURIComponent(person.id)}` }
    ]
  };
}

function freeGeneralKnowledgeAnswer(question) {
  const q = cleanText(question, 1200);
  const nq = normalizeArabicForMatch(q);
  if (!q) return { answer: "اكتب سؤالك أولًا." };

  const hasAny = (...words) => words.some((w) => nq.includes(normalizeArabicForMatch(w)));

  const numericExpression = q.replace(/[٠-٩]/g, (d) => "٠١٢٣٤٥٦٧٨٩".indexOf(d)).match(/^[\s\d+\-*/().,%]+$/);
  if (numericExpression && /[+\-*/]/.test(q)) {
    try {
      const safe = q.replace(/,/g, ".").replace(/%/g, "/100");
      if (/^[\s\d+\-*/().]+$/.test(safe)) {
        const result = Function(`"use strict"; return (${safe});`)();
        if (Number.isFinite(result)) return { answer: `ناتج العملية هو: ${result}` };
      }
    } catch (_) {}
  }

  const greeting = answerGreetingQuestion(q);
  if (greeting) return greeting;

  const dateTime = answerDateTimeQuestion(q);
  if (dateTime) return dateTime;

  if (hasAny("انت مين", "من انت", "ما وظيفتك", "تقدر تعمل ايه")) {
    return { answer: "أنا مساعد الموقع الذكي. أستطيع البحث في بيانات العائلة، شرح طريقة إضافة البيانات وتتبع الطلبات، حساب صلة القرابة، والإجابة على أسئلة عامة بسيطة بدون مفاتيح أو اشتراكات. الأسئلة اللحظية مثل أخبار اليوم أو نتائج المباريات المباشرة تحتاج مصدر خارجي محدث." };
  }

  if (hasAny("رياضه", "رياضة", "كره", "كرة", "مباراه", "مباراة", "الدوري", "كاس", "كأس")) {
    return { answer: "أقدر أساعدك في معلومات رياضية عامة مثل شرح القوانين والبطولات والمراكز وطريقة احتساب النقاط. لكن النتائج المباشرة أو أخبار اليوم لا أستطيع تأكيدها بدون مصدر خارجي محدث. اكتب سؤالك الرياضي بالتحديد وسأجيبك بما أستطيع." };
  }

  if (hasAny("اخبار", "أخبار", "خبر اليوم", "اخر الاخبار", "آخر الأخبار")) {
    return { answer: "أستطيع عرض أخبار الموقع المنشورة من قاعدة البيانات. أما أخبار العالم الحالية أو العاجلة فلا يمكنني ضمانها بدون اتصال بمصدر أخبار مباشر. اسألني عن أخبار العائلة أو الأخبار المنشورة في الموقع وسأعرضها لك." };
  }

  if (hasAny("السعوديه", "السعودية", "مصر", "القاهره", "القاهرة", "الرياض", "جده", "جدة")) {
    return { answer: "أقدر أساعدك بمعلومات عامة مستقرة عن الدول والمدن، لكن أي بيانات متغيرة مثل الطقس والأسعار والأخبار الحالية تحتاج مصدر محدث. اكتب السؤال بشكل محدد مثل: ما عاصمة السعودية؟ أو ما معنى العنوان الوطني؟" };
  }

  if (hasAny("الذكاء الاصطناعي", "ai", "artificial intelligence")) {
    return { answer: "الذكاء الاصطناعي هو أنظمة وبرامج تستطيع تحليل البيانات وفهم النصوص أو الصور واتخاذ قرارات أو توليد إجابات بناءً على أنماط تعلمتها. في هذا الموقع أعمل كمساعد داخلي يربط بين أسئلة المستخدم وبيانات العائلة والموقع." };
  }

  if (hasAny("نصيحه", "نصيحة", "اعمل ايه", "أعمل إيه", "ما رأيك", "رايك")) {
    return { answer: "أقدر أساعدك بنصيحة عامة، لكن الأفضل تكتب لي تفاصيل أكثر: الموضوع، الهدف، والاختيارات المتاحة. لو السؤال طبي أو قانوني أو مالي، اعتبر إجابتي توجيهًا عامًا وليس بديلًا عن مختص." };
  }

  if (hasAny("شكرا", "شكر", "تسلم", "تمام")) {
    return { answer: "العفو، تحت أمرك دائمًا." };
  }

  return clarifyAssistantAnswer();
}

async function answerGeneralAssistant(question) {
  const q = cleanText(question, 1200);
  if (!q) return { answer: "اكتب سؤالك أولًا." };

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return freeGeneralKnowledgeAnswer(q);
  }

  if (typeof fetch !== "function") {
    return freeGeneralKnowledgeAnswer(q);
  }

  const model = process.env.OPENAI_MODEL || "gpt-4.1-mini";
  const systemPrompt = [
    "أنت مساعد عربي لموقع شجرة عائلة.",
    "أجب بوضوح وباختصار مفيد.",
    "عند السؤال عن الموقع أو العائلة اعتمد فقط على البيانات التي يقدمها النظام في الردود الداخلية ولا تخترع بيانات عائلية.",
    "عند السؤال العام خارج الموقع يمكنك الإجابة كمساعد عام.",
    "لا تعرض بيانات خاصة مثل رقم الجوال أو البريد أو العنوان إلا إذا كانت متاحة صراحة للعامة."
  ].join(" ");

  try {
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model,
        input: [
          { role: "system", content: systemPrompt },
          { role: "user", content: q }
        ]
      })
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      console.error("OpenAI assistant error:", response.status, errText.slice(0, 500));
      return freeGeneralKnowledgeAnswer(q);
    }

    const data = await response.json();
    const outputText = data.output_text || (Array.isArray(data.output) ? data.output.flatMap((item) => item.content || []).map((c) => c.text || "").join("\n").trim() : "");
    return { answer: outputText || freeGeneralKnowledgeAnswer(q).answer };
  } catch (err) {
    console.error("General AI assistant failed:", err);
    return freeGeneralKnowledgeAnswer(q);
  }
}

async function answerSiteAssistant(question) {
  const q = cleanText(question, 600);
  const nq = normalizeArabicForMatch(q);
  if (!q) return { answer: "اكتب سؤالك أولًا عن الموقع أو العائلة." };

  const greetingAnswer = answerGreetingQuestion(q);
  if (greetingAnswer) return greetingAnswer;

  const dateTimeAnswer = answerDateTimeQuestion(q);
  if (dateTimeAnswer) return dateTimeAnswer;

  const mathAnswer = answerSimpleMathQuestion(q);
  if (mathAnswer) return mathAnswer;

  if (isFamilyHistoryQuestion(q)) {
    return await getFamilyHistoryAssistantAnswer();
  }

  if (isAgeQuestion(q)) {
    const ageAnswer = await answerPersonAgeQuestion(q);
    if (ageAnswer) return ageAnswer;
  }

  if (isChildrenCountQuestion(q)) {
    const childrenAnswer = await answerChildrenCountQuestion(q);
    if (childrenAnswer) return childrenAnswer;
  }

  const faqAnswer = answerWebsiteFAQ(q);
  if (faqAnswer) return faqAnswer;

  const ref = q.match(/FAM-\d{4}-[A-Z0-9]+/i)?.[0];
  if (ref || nq.includes("طلب") || nq.includes("تتبع")) {
    if (ref) {
      const request = await findPersonRequestByReference(ref);
      if (!request) return { answer: "لم يتم العثور على طلب بهذا الرقم المرجعي. تأكد من كتابة الرمز بشكل صحيح.", link: "/submit-person#track-request", linkLabel: "فتح تتبع الطلب" };
      const statusMap = { pending:"قيد المراجعة", approved:"تمت الموافقة", rejected:"تم الرفض" };
      let answer = `حالة طلب ${request.name}: ${statusMap[request.status] || request.status}.`;
      if (request.status === "rejected") answer += `\nسبب الرفض: ${request.admin_note || "لم يتم ذكر سبب محدد."}`;
      if (request.status === "approved") answer += `\nتمت إضافة الاسم إلى الشجرة.`;
      return { answer, link: request.created_person_id ? `/?focus=${request.created_person_id}` : "/submit-person#track-request", linkLabel: request.created_person_id ? "شاهد موقعك في الشجرة" : "فتح صفحة التتبع" };
    }
    return { answer: "لتتبع طلب إضافة البيانات، افتح صفحة إضافة بياناتك ثم اكتب الرقم المرجعي في قسم تتبع الطلب.", link: "/submit-person#track-request", linkLabel: "تتبع الطلب" };
  }

  const kinshipNames = extractKinshipNamesFromQuestion(q);
  if (kinshipNames) {
    const result = await calculateKinshipByNames(kinshipNames.a, kinshipNames.b);
    return {
      answer: result.message || "لم أتمكن من حساب صلة القرابة من البيانات الحالية.",
      link: `/kinship?person_a=${encodeURIComponent(kinshipNames.a)}&person_b=${encodeURIComponent(kinshipNames.b)}`,
      linkLabel: "فتح صفحة صلة القرابة",
      actions: [
        { label: "عرض الحساب في صفحة صلة القرابة", url: `/kinship?person_a=${encodeURIComponent(kinshipNames.a)}&person_b=${encodeURIComponent(kinshipNames.b)}` }
      ]
    };
  }

  if (nq.includes("صله") || nq.includes("قرابه") || nq.includes("قريبي")) {
    return { answer: "اكتب السؤال بصيغة: ما صلة القرابة بين الاسم الأول والاسم الثاني، وسأحسبها لك مباشرة من بيانات الشجرة. مثال: ما صلة القرابة بين أحمد محمد علي وخالد يوسف علي.", link: "/kinship", linkLabel: "فتح صفحة صلة القرابة" };
  }

  if (nq.includes("اضيف") || nq.includes("اضافه") || nq.includes("بياناتي")) {
    return { answer: "يمكنك إرسال بياناتك من صفحة إضافة بياناتك. بعد الإرسال سيظهر لك رقم مرجعي، احتفظ به لتتبع حالة الطلب حتى تتم مراجعته من الإدارة.", link: "/submit-person", linkLabel: "إضافة بياناتك" };
  }

  if (nq.includes("عدد") || nq.includes("احصائيات") || nq.includes("كم")) {
    const stats = await getSiteStats();
    return { answer: `إحصائيات الموقع الحالية:\nإجمالي الأفراد: ${stats.total}\nعدد الذكور: ${stats.males}\nعدد الإناث: ${stats.females}\nالأسماء المكررة: ${stats.duplicateNames || 0}\nالسير الذاتية: ${stats.honorItems || 0}\nالأخبار المنشورة: ${stats.activeNews || 0}` };
  }

  if (nq.includes("خبر") || nq.includes("اخبار")) {
    const latest = await get(`SELECT id,title,summary FROM news_posts WHERE COALESCE(is_active,1)=1 ORDER BY COALESCE(is_pinned,0) DESC, id DESC LIMIT 1`);
    if (!latest) return { answer: "لا توجد أخبار منشورة حاليًا.", link: "/news", linkLabel: "فتح الأخبار" };
    return { answer: `آخر خبر منشور: ${latest.title}\n${cleanText(latest.summary || "", 180)}`, link: `/news/${latest.id}`, linkLabel: "قراءة الخبر" };
  }

  const { rows, byId } = await getPersonsForRelationship();
  const personQuery = stripAssistantNameNoise(q);
  const shouldSearchPerson = isLikelyPersonLookupQuestion(q) || isProbablyNameText(personQuery);
  const match = shouldSearchPerson ? matchPersonByFlexibleName(personQuery || q, rows, byId) : { status: "not_found", matches: [] };
  if (match.status === "matched") {
    return await buildPersonAssistantAnswer(match.matches[0], rows, byId);
  }
  if (match.status === "multiple") {
    return {
      answer: `وجدت أكثر من نتيجة محتملة. اختر الشخص المقصود من الروابط التالية أو اكتب الاسم رباعي لتحديده بدقة:\n${match.matches.map((x, i)=>`${i+1}- ${x.name} (${x.lineage_label})`).join("\n")}`,
      actions: match.matches.flatMap((x)=>[
        { label: `موقع ${x.name} في الشجرة`, url: `/?focus=${x.id}` },
        { label: `سيرة ${x.name}`, url: `/honor?personId=${encodeURIComponent(x.id)}` }
      ]).slice(0, 10)
    };
  }
  if (shouldSearchPerson) {
    return {
      answer: `لم أجد شخصًا مطابقًا لاسم "${personQuery || q}" داخل الشجرة. برجاء كتابة الاسم ثلاثي أو رباعي، أو التأكد من طريقة كتابة الاسم.`
    };
  }

  return { answer: "", general: true };
}


/* =========================
   Assistant precision fixes: Saudi-style names, Ramadan countdown, person children questions
   ========================= */
function namePartsForMatch(value) {
  const stop = new Set(["بن", "ابن", "بنت", "ال", "آل", "ال", "خاشقجي", "الخاشقجي"]);
  return normalizeArabicForMatch(value)
    .split(" ")
    .filter(Boolean)
    .filter((part) => !stop.has(part));
}

function firstNameForMatch(value) {
  return namePartsForMatch(value)[0] || "";
}

function assistantHasMonthCountdownIntent(question) {
  const nq = normalizeArabicForMatch(question);
  const hasCountdownWords = ["باقي", "متبقي", "متي", "موعد", "يبدا", "يبدأ", "كم يوم", "كم شهر"].some((w) => nq.includes(normalizeArabicForMatch(w)));
  const hasMonth = [...HIJRI_MONTHS, ...GREGORIAN_MONTHS].some((item) => item.names.some((name) => nq.includes(normalizeMonthQuery(name))));
  return hasCountdownWords && hasMonth;
}

function detectMonthCountdown(question) {
  const nq = normalizeArabicForMatch(question);
  if (!assistantHasMonthCountdownIntent(question)) return null;

  for (const item of HIJRI_MONTHS) {
    if (item.names.some((name) => nq.includes(normalizeMonthQuery(name)))) {
      const next = findNextHijriMonthStart(item.n);
      if (!next) return { answer: "لا أستطيع حساب هذا الشهر الهجري بدقة على الخادم الحالي." };
      const dayWord = next.days === 0 ? "اليوم" : `${arabicNumber(next.days)} يوم`;
      return {
        answer: `باقي على ${item.names[0]} تقريبًا ${dayWord}.\nالتاريخ المتوقع لبداية الشهر: ${formatGregorianDateArabic(next.date)}.\nملاحظة: الأشهر الهجرية تعتمد على الرؤية الشرعية، لذلك قد يختلف التاريخ يومًا بالزيادة أو النقصان.`
      };
    }
  }

  for (const item of GREGORIAN_MONTHS) {
    if (item.names.some((name) => nq.includes(normalizeMonthQuery(name)))) {
      const next = findNextGregorianMonthStart(item.n);
      const dayWord = next.days === 0 ? "اليوم" : `${arabicNumber(next.days)} يوم`;
      return {
        answer: `باقي على شهر ${item.names[0]} ${dayWord} تقريبًا.\nبدايته تكون في ${formatGregorianDateArabic(next.date)}.`
      };
    }
  }
  return null;
}

function extractNameFromChildrenQuestion(question) {
  let q = removeArabicQuestionNoise(question);
  q = q
    .replace(/\b(?:كم\s+عدد|كم|عدد)\s+(?:ولد|بنت|ابن|ابنة|اولاد|أولاد|ابناء|أبناء|عيال|اطفال|أطفال)\b/gi, " ")
    .replace(/\b(?:وكم|و\s+كم)\s*(?:عدد\s+)?(?:ولد|بنت|ابن|ابنة|اولاد|أولاد|ابناء|أبناء)\b/gi, " ")
    .replace(/\b(?:عنده|عندها|لديه|لديها|له|لها|معه|معها)\b/gi, " ")
    .replace(/\b(?:من|ل|لـ)\b$/gi, " ")
    .replace(/\s+/g, " ")
    .trim();

  const prefixPatterns = [
    /^(?:كم\s+عدد\s+ابناء|كم\s+عدد\s+أبناء|كم\s+عدد\s+اولاد|كم\s+عدد\s+أولاد|كم\s+عدد\s+ولد|كم\s+عدد\s+بنت|كم\s+ابناء|كم\s+أبناء|كم\s+اولاد|كم\s+أولاد|كم\s+ولد|كم\s+بنت|عدد\s+ابناء|عدد\s+أبناء|عدد\s+اولاد|عدد\s+أولاد|عدد\s+ولد|عدد\s+بنت|اولاد|أولاد|ابناء|أبناء|بنات|عيال)\s+/i,
    /^(?:اعرض|قول\s+لي|قولي|ابي|ابغى|اريد|عايز)\s+/i,
  ];
  for (const re of prefixPatterns) q = q.replace(re, "").trim();
  return stripAssistantNameNoise(q);
}

async function answerChildrenCountQuestion(question) {
  const { rows, byId } = await getPersonsForRelationship();
  const name = extractNameFromChildrenQuestion(question);
  const match = matchPersonByFlexibleName(name, rows, byId);
  if (match.status === "matched") {
    const person = match.matches[0];
    const children = rows.filter((x)=>Number(x.father_id)===Number(person.id)||Number(x.mother_id)===Number(person.id));
    const sons = children.filter((c)=>genderIsMale(c));
    const daughters = children.filter((c)=>genderIsFemale(c));
    const unknown = children.length - sons.length - daughters.length;
    const lines = [`${person.name} لديه/لديها ${arabicNumber(children.length)} من الأبناء المسجلين في الشجرة.`];
    lines.push(`الأولاد: ${arabicNumber(sons.length)}.`);
    lines.push(`البنات: ${arabicNumber(daughters.length)}.`);
    if (unknown > 0) lines.push(`غير محدد النوع: ${arabicNumber(unknown)}.`);
    if (children.length) lines.push(`الأسماء: ${children.map(c=>c.name).join("، ")}.`);
    return { answer: lines.join("\n"), actions: [{ label: "عرض موقعه في الشجرة", url: `/?focus=${person.id}` }] };
  }
  if (match.status === "multiple") return { answer: `وجدت أكثر من شخص بهذا الاسم. اكتب الاسم رباعي لتحديد الشخص بدقة:\n${match.matches.map((x,i)=>`${i+1}- ${x.name} (${x.lineage_label})`).join("\n")}` };
  return null;
}

function extractNameAfterPatterns(question, patterns) {
  let q = removeArabicQuestionNoise(question);
  q = q.replace(/\b(بن|ابن)\b/g, " ").replace(/\s+/g, " ").trim();
  for (const re of patterns) {
    const m = q.match(re);
    if (m && m[1]) return stripAssistantNameNoise(m[1]);
  }
  return stripAssistantNameNoise(q);
}

function cleanKinshipNamePart(value) {
  return cleanText(String(value || "")
    .replace(/^(?:من|عن|اسم|الاسم|الشخص|هو|هوا|هوه|هي|الأول|الاول|الثاني|التاني)\s+/i, "")
    .replace(/\s+(?:من\s+العائلة|في\s+الشجرة|داخل\s+الشجرة|بالشجرة)$/i, "")
    .trim(), 220);
}

function extractKinshipNamesFromQuestion(question) {
  let q = removeArabicQuestionNoise(question);
  q = q
    .replace(/إيه/g, "ايه")
    .replace(/أيه/g, "ايه")
    .replace(/اي\s+/g, "ايه ")
    .replace(/ما\s+هي\s+/g, "")
    .replace(/ما\s+هو\s+/g, "")
    .replace(/ما\s+/g, "")
    .replace(/صلة\s+القرابة|صله\s+القرابه|صلة\s+القربى/g, "صلة القرابة")
    .replace(/قرابيه|قرابة|قرايب|قرايبين/g, "قرابة");

  const patterns = [
    /(?:صلة\s+القرابة|صلة|قرابة)\s+(?:بين\s+)?(.+?)\s+(?:و|وبين|مع)\s+(.+)$/i,
    /(?:ايه|ما)\s+(?:صلة\s+)?(?:قرابة|صلة)\s+(.+?)\s+(?:و|وبين|مع)\s+(.+)$/i,
    /(?:بين\s+)?(.+?)\s+(?:و|وبين|مع)\s+(.+?)\s+(?:ايه|ما)\s*(?:صلة|قرابة|يقربوا|يقربو|يقربان)?$/i,
    /(.+?)\s+(?:يقرب|تقرب|قريب|قريبة|قريبي)\s+(?:ايه\s+)?(?:من|لـ|ل)?\s+(.+)$/i,
    /(.+?)\s+(?:ايه|ما)\s+(?:يقرب|تقرب|صلة|قرابة)\s+(?:من|لـ|ل)?\s+(.+)$/i,
    /(.+?)\s+(?:وش|ايش|ايه)\s+(?:قرابته|قرابتها|صلته|صلتها)\s+(?:من|مع|لـ|ل)\s+(.+)$/i
  ];

  for (const re of patterns) {
    const m = q.match(re);
    if (m && m[1] && m[2]) {
      const a = cleanKinshipNamePart(m[1]);
      const b = cleanKinshipNamePart(m[2]);
      if (namePartsForMatch(a).length >= 1 && namePartsForMatch(b).length >= 1) return { a, b };
    }
  }
  return null;
}

async function answerSiteAssistant(question) {
  const q = cleanText(question, 600);
  const nq = normalizeArabicForMatch(q);
  if (!q) return { answer: "اكتب سؤالك أولًا عن الموقع أو العائلة." };

  const greetingAnswer = answerGreetingQuestion(q);
  if (greetingAnswer) return greetingAnswer;

  const dateTimeAnswer = answerDateTimeQuestion(q);
  if (dateTimeAnswer) return dateTimeAnswer;

  const mathAnswer = answerSimpleMathQuestion(q);
  if (mathAnswer) return mathAnswer;

  if (isFamilyHistoryQuestion(q)) {
    return await getFamilyHistoryAssistantAnswer();
  }

  const ref = q.match(/FAM-\d{4}-[A-Z0-9]+/i)?.[0];
  if (ref || nq.includes("طلب") || nq.includes("تتبع")) {
    if (ref) {
      const request = await findPersonRequestByReference(ref);
      if (!request) return { answer: "لم يتم العثور على طلب بهذا الرقم المرجعي. تأكد من كتابة الرمز بشكل صحيح.", link: "/submit-person#track-request", linkLabel: "فتح تتبع الطلب" };
      const statusMap = { pending:"قيد المراجعة", approved:"تمت الموافقة", rejected:"تم الرفض" };
      let answer = `حالة طلب ${request.name}: ${statusMap[request.status] || request.status}.`;
      if (request.status === "rejected") answer += `\nسبب الرفض: ${request.admin_note || "لم يتم ذكر سبب محدد."}`;
      if (request.status === "approved") answer += `\nتمت إضافة الاسم إلى الشجرة.`;
      return { answer, link: request.created_person_id ? `/?focus=${request.created_person_id}` : "/submit-person#track-request", linkLabel: request.created_person_id ? "شاهد موقعك في الشجرة" : "فتح صفحة التتبع" };
    }
    return { answer: "لتتبع طلب إضافة البيانات، افتح صفحة إضافة بياناتك ثم اكتب الرقم المرجعي في قسم تتبع الطلب.", link: "/submit-person#track-request", linkLabel: "تتبع الطلب" };
  }

  const kinshipNames = extractKinshipNamesFromQuestion(q);
  if (kinshipNames) {
    const result = await calculateKinshipByNames(kinshipNames.a, kinshipNames.b);
    return {
      answer: result.message || "لم أتمكن من حساب صلة القرابة من البيانات الحالية.",
      actions: [
        { label: "عرض الحساب في صفحة صلة القرابة", url: `/kinship?person_a=${encodeURIComponent(kinshipNames.a)}&person_b=${encodeURIComponent(kinshipNames.b)}` }
      ]
    };
  }

  if (isAgeQuestion(q)) {
    const ageAnswer = await answerPersonAgeQuestion(q);
    if (ageAnswer) return ageAnswer;
  }

  if (isChildrenCountQuestion(q)) {
    const childrenAnswer = await answerChildrenCountQuestion(q);
    if (childrenAnswer) return childrenAnswer;
    return { answer: "اكتب اسم الشخص ثلاثي أو رباعي بعد السؤال. مثال: وسيم بن إبراهيم بن حسن عنده كم ولد وكم بنت؟" };
  }

  const faqAnswer = answerWebsiteFAQ(q);
  if (faqAnswer) return faqAnswer;

  if (nq.includes("صله") || nq.includes("قرابه") || nq.includes("قريبي")) {
    return { answer: "اكتب اسمين واضحين لأحسب صلة القرابة مباشرة. مثال: ما صلة القرابة بين فلان بن فلان وفلان بن فلان؟", link: "/kinship", linkLabel: "فتح صفحة صلة القرابة" };
  }

  if (nq.includes("اضيف") || nq.includes("اضافه") || nq.includes("بياناتي")) {
    return { answer: "يمكنك إرسال بياناتك من صفحة إضافة بياناتك. بعد الإرسال سيظهر لك رقم مرجعي، احتفظ به لتتبع حالة الطلب حتى تتم مراجعته من الإدارة.", link: "/submit-person", linkLabel: "إضافة بياناتك" };
  }

  if (nq.includes("خبر") || nq.includes("اخبار")) {
    const latest = await get(`SELECT id,title,summary FROM news_posts WHERE COALESCE(is_active,1)=1 ORDER BY COALESCE(is_pinned,0) DESC, id DESC LIMIT 1`);
    if (!latest) return { answer: "لا توجد أخبار منشورة حاليًا.", link: "/news", linkLabel: "فتح الأخبار" };
    return { answer: `آخر خبر منشور: ${latest.title}\n${cleanText(latest.summary || "", 180)}`, link: `/news/${latest.id}`, linkLabel: "قراءة الخبر" };
  }

  const { rows, byId } = await getPersonsForRelationship();
  const personQuery = stripAssistantNameNoise(q);
  const shouldSearchPerson = isLikelyPersonLookupQuestion(q) || isProbablyNameText(personQuery);
  const match = shouldSearchPerson ? matchPersonByFlexibleName(personQuery || q, rows, byId) : { status: "not_found", matches: [] };
  if (match.status === "matched") return await buildPersonAssistantAnswer(match.matches[0], rows, byId);
  if (match.status === "multiple") {
    return {
      answer: `وجدت أكثر من نتيجة محتملة. اختر الشخص المقصود من الروابط التالية أو اكتب الاسم رباعي لتحديده بدقة:\n${match.matches.map((x, i)=>`${i+1}- ${x.name} (${x.lineage_label})`).join("\n")}`,
      actions: match.matches.flatMap((x)=>[
        { label: `موقع ${x.name} في الشجرة`, url: `/?focus=${x.id}` },
        { label: `سيرة ${x.name}`, url: `/honor?personId=${encodeURIComponent(x.id)}` }
      ]).slice(0, 10)
    };
  }
  if (shouldSearchPerson) {
    return { answer: `لم أجد شخصًا مطابقًا لاسم "${personQuery || q}" داخل الشجرة. جرّب كتابته بالصيغة السعودية مثل: الاسم بن الأب بن الجد، أو اكتب الاسم ثلاثي/رباعي بدون لقب العائلة.` };
  }

  const explicitStats = ["احصائيات", "إحصائيات", "عدد افراد", "عدد أفراد", "كم عدد افراد", "كم عدد أفراد", "كم شخص", "كم فرد", "اجمالي الافراد", "إجمالي الأفراد"].some((x)=>nq.includes(normalizeArabicForMatch(x)));
  if (explicitStats) {
    const stats = await getSiteStats();
    return { answer: `إحصائيات الموقع الحالية:\nإجمالي الأفراد: ${stats.total}\nعدد الذكور: ${stats.males}\nعدد الإناث: ${stats.females}\nالأسماء المكررة: ${stats.duplicateNames || 0}\nالسير الذاتية: ${stats.honorItems || 0}\nالأخبار المنشورة: ${stats.activeNews || 0}` };
  }

  return { answer: "لم أفهم سؤالك بشكل كافٍ. وضّح المطلوب أكثر، أو اكتب اسم الشخص ثلاثي/رباعي، أو اكتب مثلًا: من هو فلان؟ أو ما صلة القرابة بين فلان وفلان؟" };
}



/* =========================
   Enhanced Saudi/Egyptian assistant dictionary
   ========================= */
function assistantIncludesAnyNormalized(question, phrases) {
  const nq = normalizeArabicForMatch(question || "");
  return phrases.some((p) => nq.includes(normalizeArabicForMatch(p)));
}

function pickSaudiResponse(list) {
  if (!Array.isArray(list) || !list.length) return { answer: "حياك الله، تفضل وش تحتاج؟" };
  const idx = Math.floor(Math.random() * list.length);
  return { answer: list[idx] };
}

function assistantIsOnlyGreeting(question) {
  const nq = normalizeArabicForMatch(question || "").trim();
  const cleaned = nq.replace(/\s+/g, " ");
  const greetings = [
    "سلام", "السلام عليكم", "سلام عليكم", "السلامو عليكم", "السلام عليكم ورحمه الله", "هلا", "هلا والله", "يا هلا", "مرحبا", "اهلا", "أهلا", "اهلين", "أهلين", "حياك", "حي الله", "صباح الخير", "مساء الخير", "كيف الحال", "كيف حالك", "كيفك", "شلونك", "وش اخبارك", "وش علومك", "عامل ايه", "ازيك", "إزيك", "اخبارك ايه"
  ].map(normalizeArabicForMatch);
  return greetings.some((g) => cleaned === g || cleaned.startsWith(g + " "));
}

function answerGreetingQuestion(question) {
  const nq = normalizeArabicForMatch(question || "");
  if (!assistantIsOnlyGreeting(question)) return null;
  if (nq.includes(normalizeArabicForMatch("السلام")) || nq.includes(normalizeArabicForMatch("سلام عليكم"))) {
    return { answer: "وعليكم السلام ورحمة الله وبركاته، يا هلا ومرحبا. أنا سعود، مساعد الموقع. أبشر، اسألني عن أي فرد في الشجرة، صلة القرابة، تاريخ العائلة، تتبع الطلبات، أو طريقة استخدام الموقع." };
  }
  if (nq.includes(normalizeArabicForMatch("صباح"))) {
    return { answer: "صباح النور والسرور، حيّاك الله. أنا سعود، حاضر أساعدك في الشجرة، الأسماء، صلة القرابة، الطلبات، أو أي استفسار عن الموقع." };
  }
  if (nq.includes(normalizeArabicForMatch("مساء"))) {
    return { answer: "مساء الخير والنور، يا هلا والله. تفضل اسألني عن العائلة، صلة القرابة، تاريخ الموقع، أو أي شخص داخل الشجرة." };
  }
  if (nq.includes(normalizeArabicForMatch("كيف")) || nq.includes(normalizeArabicForMatch("شلون")) || nq.includes(normalizeArabicForMatch("ازيك")) || nq.includes(normalizeArabicForMatch("عامل ايه"))) {
    return { answer: "بخير ونعمة، الله يسلمك. حيّاك الله، وش تبي تعرف؟ أقدر أساعدك في بيانات العائلة، صلة القرابة، تاريخ العائلة، أو تتبع طلبك." };
  }
  return { answer: "يا هلا والله، حيّاك الله. أنا سعود، مساعدك داخل الموقع. اسألني عن شخص في الشجرة، صلة قرابة، تاريخ العائلة، أو طريقة إضافة بياناتك." };
}

function answerDateTimeQuestion(question) {
  const nq = normalizeArabicForMatch(question || "");
  const monthCountdown = detectMonthCountdown(question);
  if (monthCountdown) return monthCountdown;

  const wantsHijri = assistantIncludesAnyNormalized(question, [
    "كم اليوم في التاريخ الهجري", "تاريخ اليوم هجري", "التاريخ الهجري", "كم التاريخ الهجري", "اليوم هجري", "النهارده هجري", "تاريخ هجري"
  ]);
  const wantsGregorian = assistantIncludesAnyNormalized(question, [
    "كم اليوم في التاريخ الميلادي", "تاريخ اليوم ميلادي", "التاريخ الميلادي", "كم التاريخ الميلادي", "اليوم ميلادي", "النهارده ميلادي", "تاريخ ميلادي"
  ]);
  const wantsDayOrDate = assistantIncludesAnyNormalized(question, [
    "كم اليوم", "انهارده اي", "النهارده اي", "اليوم اي", "اليوم ايه", "النهارده كام", "اليوم كام", "تاريخ اليوم", "اي تاريخ اليوم", "كم التاريخ", "وش تاريخ اليوم", "ايش تاريخ اليوم"
  ]);
  const wantsTime = assistantIncludesAnyNormalized(question, [
    "كم الساعة", "كم الساعه", "الساعة كم", "الساعه كم", "الوقت الان", "الوقت الآن", "اي وقت", "الوقت كام", "الساعة كام", "الساعه كام", "كام الساعة", "كام الساعه", "الوقت الحين", "الساعه الحين", "كم الوقت"
  ]);

  if (!wantsHijri && !wantsGregorian && !wantsDayOrDate && !wantsTime) return null;
  const now = new Date();
  const parts = [];
  if (wantsTime) parts.push(`الوقت الآن حسب توقيت السعودية: ${formatTimeArabic(now)}.`);
  if (wantsHijri) parts.push(`التاريخ الهجري اليوم: ${formatHijriDateArabic(now)}.`);
  if (wantsGregorian) parts.push(`التاريخ الميلادي اليوم: ${formatGregorianDateArabic(now)}.`);
  if (wantsDayOrDate && !wantsHijri && !wantsGregorian) {
    parts.push(`اليوم: ${formatGregorianDateArabic(now)}.`);
    parts.push(`وبالهجري: ${formatHijriDateArabic(now)}.`);
  }
  return { answer: parts.join("\n") };
}



/* =========================
   Expanded Saud assistant dictionary from user-provided FAQ
   ========================= */
function answerSaudExtendedDictionary(question) {
  const q = cleanText(question || "", 1400);
  const nq = normalizeArabicForMatch(q);
  if (!nq) return null;
  const hasAny = (...words) => words.some((w) => nq.includes(normalizeArabicForMatch(w)));
  const startsAny = (...words) => words.some((w) => nq.startsWith(normalizeArabicForMatch(w)));

  // تعريف سعود وشخصيته
  if (hasAny("يا سعود", "سعود ساعدني", "هل انت مثل شات جي بي تي", "هل أنت مثل chatgpt", "هل انت تابع للموقع", "هل ترد باللهجة السعودية", "تعرف لهجات السعودية", "كيف استخدمك")) {
    return { answer: "يا هلا والله، أنا سعود، مساعد ذكي لموقع أسرة خاشقجي. أقدر أساعدك في شجرة العائلة، صلة القرابة، تاريخ العائلة، الأخبار والمناسبات، كتابة النصوص والتهاني والقصائد، الحسابات، التلخيص، وإرشادك لاستخدام الموقع خطوة بخطوة." };
  }

  // شرح الموقع العام
  if (hasAny("وش هذا الموقع", "ايش هذا الموقع", "ايه الموقع ده", "ما هو موقع اسرة خاشقجي", "موقع اسرة خاشقجي", "وصف الموقع", "اقترح وصف للموقع", "رسالة ترحيب للموقع")) {
    return { answer: "هذا موقع خاص بأسرة خاشقجي، هدفه تنظيم شجرة العائلة، توثيق الأسماء والروابط العائلية، نشر الأخبار والمناسبات، حفظ السير الذاتية والنبذات، وتعزيز صلة الرحم بين أفراد الأسرة." };
  }

  if (hasAny("وين شجرة العائلة", "فين شجرة العائلة", "افتح الشجرة", "ابي اشوف الشجرة", "ابغى اشوف كامل الشجرة", "شجرة العائلة فين")) {
    return { answer: "تقدر تشوف شجرة العائلة من الصفحة الرئيسية. استخدم البحث لكتابة اسم الشخص، وإذا وجدت النتيجة ينتقل الموقع مباشرة إلى مكانه داخل الشجرة.", link: "/", linkLabel: "فتح شجرة العائلة" };
  }

  if (hasAny("كيف ابحث عن شخص", "كيف أبحث عن شخص", "ابحث عن فلان", "ما لقيت الاسم", "الاسم ما يظهر", "كيف ابحث بالجوال", "كيف أجد تفاصيل فرد")) {
    return { answer: "للبحث عن شخص، اكتب اسمه أو جزءًا من اسمه في خانة البحث داخل الشجرة. إذا كان الاسم مكررًا أو غير واضح، جرّب كتابته ثلاثي أو رباعي، أو بصيغة: الاسم بن الأب بن الجد. إذا لم يظهر فقد يكون غير مضاف أو مكتوبًا بطريقة مختلفة." };
  }

  // صلة القرابة والأنساب
  if (hasAny("ما معنى شجرة العائلة", "ايش معنى شجرة العائلة", "وش معنى شجرة العائلة")) {
    return { answer: "شجرة العائلة هي عرض منظم يوضح العلاقة بين أفراد الأسرة: الآباء، الأبناء، الإخوة، الأجداد، الأحفاد، والفروع المختلفة." };
  }

  if (hasAny("من هو جد الاسرة", "جد الاسرة", "اصل العائلة", "اصل الاسرة", "نسب العائلة", "نسب الاسرة")) {
    return { answer: "هذه المعلومة تعتمد على البيانات الموثقة داخل الموقع وصفحة النبذة. أقدر أساعدك بما هو مسجل في الموقع، وإذا كانت المعلومة غير موجودة تحتاج مراجعة من الإدارة أو من موثقي الأسرة." };
  }

  if (hasAny("كيف ابلغ عن خطا في النسب", "خطا في النسب", "غلط في النسب", "تصحيح النسب", "النسب غير صحيح")) {
    return { answer: "إذا لاحظت خطأ في النسب، تواصل مع الإدارة واذكر الاسم الحالي والتصحيح المطلوب، ويفضل إضافة توضيح أو مصدر. الإدارة تراجع التعديل قبل اعتماده حفاظًا على دقة الشجرة.", link: "/support", linkLabel: "إبلاغ الإدارة" };
  }

  if (hasAny("كيف اضيف مولود", "اضافة مولود", "مولود جديد", "كيف اضيف زواج", "اضافة زواج", "توثيق زواج")) {
    return { answer: "لإضافة مولود أو زواج، أرسل طلب إضافة بيانات من الموقع أو تواصل مع الإدارة، واكتب الأسماء كاملة والتاريخ إن وجد وأي بيانات داعمة. الإدارة تراجع البيانات قبل ظهورها في الشجرة.", link: "/submit-person", linkLabel: "إضافة بيانات" };
  }

  if (hasAny("كيف احذف فرد", "حذف فرد", "امسح شخص", "حذف شخص من الشجرة")) {
    return { answer: "حذف فرد من الشجرة إجراء حساس لأنه يؤثر على النسب والروابط العائلية. لذلك يتم فقط من الإدارة وبعد مراجعة السبب والتأكد من صحة الطلب.", link: "/support", linkLabel: "التواصل مع الإدارة" };
  }

  // إنشاء محتوى: قصائد وتهاني وتعازي وأخبار
  if (hasAny("اكتب قصيدة", "قصيدة عن", "اكتب شعر", "بيت شعر", "قصيدة فخر", "قصيدة ترحيب", "قصيدة عن خاشقجي", "قصيدة افتتاح", "شعر باللهجة السعودية")) {
    return { answer: "أبشر، هذه قصيدة قصيرة:\nيا خاشقجي يا اسم عزٍ ومقدار\nيا رمز طيبٍ بالوفا دوم مذكور\nتاريخكم نورٍ على كل الأقطار\nومجدكم باقي على مر العصور\n\nوإذا تبيها لاسم شخص أو مناسبة معينة، اكتب لي الاسم والمناسبة وأصيغها لك بشكل أخص." };
  }

  if (hasAny("اكتب تهنئة زواج", "تهنئة زواج")) {
    return { answer: "نبارك للعروسين زواجهما المبارك، ونسأل الله أن يجمع بينهما في خير، ويرزقهما السعادة والمودة والذرية الصالحة." };
  }
  if (hasAny("اكتب تهنئة مولود", "تهنئة مولود", "مولود جديد")) {
    return { answer: "نبارك لكم المولود الجديد، ونسأل الله أن يجعله من مواليد السعادة ومن الذرية الصالحة، وأن يقر به عين والديه." };
  }
  if (hasAny("اكتب تهنئة تخرج", "تهنئة تخرج", "تهنئة نجاح", "مبروك النجاح")) {
    return { answer: "نبارك لكم هذا الإنجاز المشرّف، ونسأل الله أن يجعله بداية لمستقبل مليء بالنجاح والتوفيق والتميز." };
  }
  if (hasAny("اكتب تهنئة عيد", "تهنئة عيد", "اكتب تهنئة رمضان", "تهنئة رمضان", "مبارك عليكم الشهر")) {
    return { answer: "كل عام وأنتم بخير، أعاده الله عليكم وعلى أسرة خاشقجي الكريمة بالخير واليمن والبركات، وتقبل الله منا ومنكم صالح الأعمال." };
  }
  if (hasAny("اكتب تعزية", "تعزية", "رسالة مواساة", "خبر وفاة", "دعاء للمتوفى", "اعلان عزاء")) {
    return { answer: "إنا لله وإنا إليه راجعون. أحسن الله عزاءكم، وغفر لفقيدكم، وأسكنه فسيح جناته، وألهم أهله وذويه الصبر والسلوان." };
  }
  if (hasAny("اكتب خبر عن مولود", "اكتب خبر زواج", "اكتب خبر تخرج", "اكتب خبر اجتماع", "اكتب خبر افتتاح", "اكتب خبر تكريم", "اكتب عنوان خبر", "اكتب وصف خبر", "صياغة خبر")) {
    return { answer: "أبشر، أقدر أجهز لك خبر مناسب للنشر. أرسل لي: نوع الخبر، اسم الشخص أو المناسبة، التاريخ إن وجد، وأي تفاصيل مهمة، وسأصيغ لك خبرًا رسميًا مرتبًا." };
  }

  // إعادة صياغة وتلخيص وترجمة
  if (startsAny("عدل", "صحح", "لخص", "اختصر", "ترجم", "اشرح", "اقترح", "اكتب لي", "اكتب رسالة", "اكتب اعلان", "اكتب منشور", "اكتب دعاء", "اكتب كلمة")) {
    if (hasAny("عدل هذه الجملة", "صحح النص", "خليه رسمي", "خليه باللهجة السعودية", "خليه اقصر", "خليه أفخم", "خليه مناسب للنشر", "خليه واتساب", "إعادة صياغة")) {
      return { answer: "أبشر، أرسل النص المطلوب تعديله وسأعيد صياغته لك بشكل أوضح وأنسب للنشر أو للواتساب حسب طلبك." };
    }
    if (hasAny("لخص", "تلخيص", "اختصر الكلام", "استخرج النقاط", "حول الكلام لنقاط", "خلاصة")) {
      return { answer: "أرسل النص، وسألخصه لك بنقاط واضحة ومختصرة مع الحفاظ على المعنى." };
    }
    if (hasAny("ترجم للانجليزي", "ترجم للإنجليزي", "ترجم للعربي", "ترجمة")) {
      return { answer: "أرسل النص وحدد اللغة المطلوبة، وسأترجمه لك بأسلوب واضح ومفهوم." };
    }
    if (hasAny("اكتب لي رسالة رسمية", "اكتب رسالة", "اكتب اعلان", "اكتب إعلان", "اكتب منشور", "اقترح عنوان", "اكتب وصف", "اكتب رد واتساب", "اكتب دعاء", "اكتب كلمة قصيرة")) {
      return { answer: "أبشر، اكتب لي تفاصيل المطلوب: المناسبة، الاسم أو الجهة، وهل تريده رسمي أو ودي أو باللهجة السعودية، وسأجهزه لك بشكل مرتب." };
    }
  }

  // مساعدة إدارية داخل الموقع
  if (hasAny("كيف اضيف خبر من الادارة", "كيف أضيف خبر من الإدارة", "كيف اعدل خبر", "كيف احذف خبر", "كيف اضيف مناسبة", "كيف اضيف ناشر الخبر", "كيف اعرف نشاط الادارة", "سجل النشاط", "كيف اخلي بيانات خاصة")) {
    return { answer: "من لوحة الإدارة يمكنك إدارة الأخبار والصفحات والأفراد والسير الذاتية وطلبات الأفراد. اختر القسم المطلوب من القائمة الجانبية، ثم إضافة أو تعديل أو حذف حسب صلاحيتك. البيانات الحساسة مثل الجوال والبريد والعنوان تظهر للإدارة فقط." };
  }

  if (hasAny("كيف اراجع طلب تعديل", "كيف اراجع طلب", "طلبات الافراد", "مراجعة الطلبات", "اعتماد الطلب", "رفض الطلب")) {
    return { answer: "لمراجعة طلبات الأفراد، ادخل لوحة الإدارة ثم طلبات الأفراد. افتح الطلب، راجع البيانات، ثم اختر اعتماد لإضافته للشجرة أو رفض مع كتابة سبب واضح للمستخدم.", link: "/admin/person-requests", linkLabel: "طلبات الأفراد" };
  }

  // أفكار للموقع
  if (hasAny("اقترح تطوير للموقع", "كيف نخلي الموقع افضل", "اقترح اقسام جديدة", "افكار للموقع", "افكار محتوى", "كيف نزيد التفاعل", "اقترح شعار", "اقترح اسم لقسم")) {
    return { answer: "أقترح تطويرات مفيدة للموقع مثل: تنبيهات للطلبات الجديدة، أرشيف صور العائلة، صفحة إنجازات الأفراد، تحسين البحث في الشجرة، سجل تغييرات للأفراد، ونسخ احتياطي دوري لقاعدة البيانات والصور." };
  }

  // الخصوصية والصلاحيات
  if (hasAny("ليه ما اقدر اشوف رقم الجوال", "من يقدر يعدل البيانات", "هل اقدر اشوف عنوان شخص", "هل الموقع امن", "هل اقدر اطلب حذف بياناتي", "من يشوف بريدي", "هل اقدر ارسل مستند اثبات")) {
    return { answer: "حفاظًا على الخصوصية، البيانات الحساسة مثل الجوال والبريد والعنوان لا تظهر للعامة، وتكون للإدارة فقط. ويمكنك طلب تعديل أو حذف بياناتك من الإدارة للمراجعة.", link: "/support", linkLabel: "التواصل مع الإدارة" };
  }

  // أعطال ومشاكل تقنية
  if (hasAny("الصفحة لا تعمل", "ظهرت لي رسالة خطا", "ظهرت لي رسالة خطأ", "لا استطيع تسجيل الدخول", "نسيت كلمة المرور", "لم يصلني كود", "الصورة لا ترفع", "لا استطيع حفظ التعديل", "ظهرت بيانات خاطئة", "الرابط لا يفتح")) {
    return { answer: "جرّب تحديث الصفحة أو فتحها من متصفح آخر. وإذا استمرت المشكلة، أرسل صورة الخطأ أو نص الرسالة لإدارة الموقع مع اسم الصفحة ونوع جهازك.", link: "/support", linkLabel: "التواصل مع الإدارة" };
  }

  // ردود ختامية متنوعة
  if (hasAny("الله يوفقك", "ابشر", "تسلم", "مع السلامة", "الله يسعدك", "ما قصرت", "جزاك الله خير", "يعطيك العافية", "شكرا", "تمام")) {
    return pickSaudiResponse([
      "الله يسلمك ويحييك، أي خدمة ثانية أنا حاضر.",
      "وإياك يا رب، تفضل بأي وقت.",
      "العفو، سعدت بخدمتك. إذا احتجت شيء بالموقع أو العائلة اسألني مباشرة.",
      "في أمان الله، وحياك الله بأي وقت.",
      "الله يبشرك بالخير، أنا حاضر لأي استفسار ثاني."
    ]);
  }

  return null;
}


function answerWebsiteFAQ(question) {
  const q = cleanText(question || "", 1200);
  const nq = normalizeArabicForMatch(q);
  if (!nq) return null;
  const hasAny = (...words) => words.some((w) => nq.includes(normalizeArabicForMatch(w)));

  const weatherAnswer = answerApproxWeatherQuestion(q);
  if (weatherAnswer) return weatherAnswer;

  const extendedDictAnswer = answerSaudExtendedDictionary(q);
  if (extendedDictAnswer) return extendedDictAnswer;

  // قاموس سعودي/مصري عام مختصر للمساعد داخل الموقع
  if (hasAny("ابي مساعدة", "أبي مساعدة", "ممكن تساعدني", "عندي استفسار", "ابي اسأل", "أبي أسأل", "احتاج خدمة", "عندي مشكلة", "تكفى ساعدني", "الله يسعدك ساعدني")) {
    return pickSaudiResponse([
      "أبشر، اكتب لي طلبك أو المشكلة بالتفصيل وبمشي معك خطوة بخطوة.",
      "حياك الله، أنا معك. وضّح لي وش تحتاج وبساعدك بأوضح طريقة.",
      "ولا يهمك، اشرح لي المطلوب أو ارسل اسم الشخص/الرقم المرجعي وأنا أساعدك."
    ]);
  }

  if (hasAny("ما فهمت", "مافهمت", "وش تقصد", "وضح اكثر", "وضّح أكثر", "كيف يعني", "ممكن تعيد", "بالله فهمني", "اختصر لي", "عطني الزبدة", "وش الحل النهائي")) {
    return pickSaudiResponse([
      "أبشر، بوضحها لك ببساطة: اكتب لي هل سؤالك عن شخص في الشجرة، صلة قرابة، طلب إضافة بيانات، أو تواصل مع الإدارة؟",
      "ولا يهمك، خلنا نمشيها خطوة خطوة. اكتب اسم الشخص ثلاثي/رباعي أو الرقم المرجعي أو المشكلة اللي ظهرت لك.",
      "الزبدة: حدد لي المطلوب بكلمة واحدة مثل: شخص، قرابة، طلب، صورة، تعديل بيانات، وأنا أوجهك مباشرة."
    ]);
  }

  if (hasAny("الموقع ما يفتح", "الصفحة بيضاء", "الرابط ما يشتغل", "يطلع لي خطأ", "ما اقدر ارفع صورة", "ما أقدر أرفع صورة", "الموقع بطيء", "الخيارات ما تظهر")) {
    return { answer: "جرّب تحديث الصفحة أو فتح الموقع من متصفح آخر. لو المشكلة مستمرة، أرسل صورة الخطأ أو اسم الصفحة لإدارة الموقع من صفحة الدعم، ووضح نوع جهازك." , link: "/support", linkLabel: "التواصل مع الإدارة" };
  }

  if (hasAny("عندي شكوى", "الخدمة سيئة", "مو راضي", "برفع شكوى", "ما احد رد", "محد يرد", "عندي ملاحظة", "عندي اقتراح")) {
    return { answer: "نعتذر لك إذا واجهت مشكلة. اكتب تفاصيل الشكوى أو الملاحظة من صفحة الدعم، وستصل لإدارة الموقع لمراجعتها." , link: "/support", linkLabel: "إرسال رسالة للإدارة" };
  }

  if (hasAny("اسمك اي", "اسمك ايه", "ايش اسمك", "وش اسمك", "من انت", "انت مين", "مين انت", "تعرف نفسك", "اسم المساعد")) {
    return {
      answer: "أنا سعود، مساعد موقع شجرة العائلة. موجود هنا عشان أساعد الزوار في معرفة الأشخاص داخل الشجرة، صلة القرابة، تاريخ العائلة، تتبع طلبات إضافة البيانات، وطريقة استخدام الموقع."
    };
  }

  if (hasAny("ايش بتقدملي يا سعود", "وش تقدم لي", "ايش تقدم", "تقدر تساعدني في ايه", "تقدر تساعدني بايش", "ايش تقدر تسوي", "تعمل ايه", "بتعمل ايه", "ماذا تقدم")) {
    return {
      answer: "أبشر، أقدر أقدم لك الآتي:\n1- أبحث لك عن أي فرد داخل الشجرة وأعرض معلوماته المتاحة للعامة.\n2- أحسب صلة القرابة بين اسمين من بيانات الشجرة.\n3- أشرح تاريخ العائلة والمحطات الزمنية من صفحة النبذة.\n4- أساعدك ترسل طلب إضافة بياناتك وتتابعه بالرقم المرجعي.\n5- أجاوب على أسئلة استخدام الموقع والصفحات والأخبار والسير الذاتية.\n6- أعطيك التاريخ والوقت وبعض الإجابات العامة البسيطة بدون عرض بيانات خاصة."
    };
  }

  if (hasAny("ايش فايدتك", "وش فايدتك", "فايدتك ايه", "اهميتك ايه", "انت مفيد في ايه", "ليش استخدمك", "ليه اكلمك")) {
    return {
      answer: "فايدتي إني أختصر عليك البحث داخل الموقع. بدل ما تنتقل بين الصفحات، تقدر تسألني مباشرة عن شخص، صلة قرابة، تاريخ العائلة، طريقة إضافة بياناتك، أو حالة طلبك، وأنا أجاوبك من بيانات الموقع بشكل واضح."
    };
  }

  if (hasAny("ايش فايدة الموقع", "وش فايدة الموقع", "فايدة الموقع", "فائدة الموقع", "اهمية الموقع", "أهمية الموقع", "الموقع ليه", "ليه الموقع", "موقع العائلة يفيد بايش", "ايه فائدة الموقع")) {
    return {
      answer: "فائدة الموقع أنه يجمع بيانات العائلة في مكان واحد بشكل منظم: شجرة تفاعلية، سير ذاتية، أخبار ومناسبات، تاريخ العائلة، وصفحة لمعرفة صلة القرابة. كما يسمح لأفراد العائلة بإرسال بياناتهم للمراجعة قبل ظهورها، وهذا يساعد في حفظ النسب والذاكرة العائلية للأجيال القادمة."
    };
  }

  if (hasAny("اسم اخوي مو موجود", "اسم أخوي مو موجود", "اخوي مو موجود", "اخي مو موجود", "اسم اخويا مش موجود", "اخويا مش موجود", "اسم اختي مو موجود", "أختي مو موجود", "اختي مو موجود", "اختي مش موجودة", "اسم اختي مش موجود")) {
    return { answer: "إذا اسم أخوك أو أختك غير موجود في الشجرة، أرسل طلب إضافة فرد جديد واكتب بياناته كاملة مع اسم الأب والأم ثلاثي. ويمكنك أيضًا إرسال رسالة للإدارة تذكر فيها أسماء الإخوة/الأخوات غير المذكورين للمراجعة.", link: "/submit-person", linkLabel: "إضافة فرد جديد" };
  }

  if (hasAny("ليش اسمي مو موجود", "ليه اسمي مش موجود", "اسمي مو موجود", "اسمي مش موجود", "اسمي غير موجود", "اسمي مهو موجود", "ما لقيت اسمي", "مش لاقي اسمي")) {
    return { answer: "إذا اسمك مو موجود في الشجرة، غالبًا لم تتم إضافته بعد أو لم يتم اعتماد طلبك من الإدارة. تقدر ترسل بياناتك من صفحة إضافة بياناتك، وبعد الإرسال احتفظ بالرقم المرجعي لتتبع حالة الطلب.", link: "/submit-person", linkLabel: "إضافة بياناتك" };
  }

  if (hasAny("كيف اضيف اسمي في الشجرة", "كيف أضيف اسمي في الشجرة", "ابغى اضيف اسمي", "ابي اضيف اسمي", "عايز اضيف اسمي", "اضافة اسمي للشجرة", "اضيف نفسي في الشجرة")) {
    return { answer: "تقدر تضيف اسمك من صفحة إضافة بياناتك. اكتب بياناتك واسم الأب والأم ثلاثي، وارفع صورتك إن وجدت، ثم أرسل الطلب للمراجعة. بعد الإرسال سيظهر لك رقم مرجعي لتتبع الطلب.", link: "/submit-person", linkLabel: "إضافة بياناتك" };
  }

  if (hasAny("اسمي خطا", "اسمي خطأ", "اسمي غلط", "احتاج اعدل اسمي", "ابغى اعدل اسمي", "عايز اعدل اسمي", "تعديل اسمي")) {
    return { answer: "إذا اسمك مكتوب بشكل غير صحيح، تواصل مع إدارة الموقع من صفحة الدعم واذكر الاسم الحالي والاسم الصحيح، أو أرسل طلب تحديث بياناتك مع توضيح الخطأ. الإدارة تراجع التعديل قبل اعتماده.", link: "/support", linkLabel: "التواصل مع الإدارة" };
  }

  if (hasAny("عندي نبذة ابغى اضيفها", "ابغى اضيف نبذة", "ابي اضيف نبذة", "عايز اضيف نبذة", "اضافة نبذة", "تعديل النبذة", "عندي سيرة ذاتية", "اضافة سيرة")) {
    return { answer: "لإضافة نبذة أو سيرة عنك، أرسلها لإدارة الموقع من صفحة التواصل أو ضمن طلب إضافة/تحديث بياناتك. الإدارة تراجع النص والصور ثم تنشرها في صفحة السير الذاتية إذا كانت مناسبة.", link: "/support", linkLabel: "إرسال النبذة للإدارة" };
  }

  if (hasAny("في خطا في معلوماتي", "في خطأ في معلوماتي", "معلوماتي غلط", "بياناتي غلط", "المعلومات الي ادخلتها خطا", "المعلومات اللي ادخلتها غلط", "ايش اسوي الحين", "ماذا افعل اذا البيانات خطا")) {
    return { answer: "إذا اكتشفت خطأ في بياناتك بعد الإرسال، احتفظ بالرقم المرجعي وتواصل مع الإدارة من صفحة الدعم موضحًا التصحيح المطلوب. لو الطلب ما زال قيد المراجعة ستتم مراجعته قبل الاعتماد، ولو تم اعتماده يمكن للإدارة تعديله من لوحة التحكم.", link: "/support", linkLabel: "التواصل مع الإدارة" };
  }

  if (hasAny("عندي اخوة غير مذكورين", "اخواني غير مذكورين", "اخوتي غير مذكورين", "كيف اضيف اخواني", "كيف اضيف اخوتي", "اضافة الاخوة", "اضافة اخوان", "ابغى اضيف اخواني")) {
    return { answer: "إذا عندك إخوة غير مذكورين، الأفضل إرسال طلب إضافة لكل شخص منهم مع كتابة اسم الأب والأم ثلاثي حتى يتم ربطهم بنفس الوالدين داخل الشجرة. ويمكنك أيضًا إرسال رسالة للإدارة توضّح أسماء الإخوة الناقصين لمراجعتهم.", link: "/submit-person", linkLabel: "إضافة فرد جديد" };
  }

  if (hasAny("من الي صمم ونفذ الموقع", "من اللي صمم ونفذ الموقع", "مين صمم الموقع", "من صمم الموقع", "مين نفذ الموقع", "من نفذ الموقع", "مبرمج الموقع", "مصمم الموقع", "مين عمل الموقع")) {
    return { answer: "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803." };
  }

  if (hasAny("كيف اغير صورتي", "كيف أغير صورتي", "ابغى اغير صورتي", "ابي اغير صورتي", "عايز اغير صورتي", "تغيير صورتي", "الصورة غلط", "صورتي خطا", "صورتي خطأ")) {
    return { answer: "لتغيير صورتك، تواصل مع إدارة الموقع من صفحة الدعم وأرسل الاسم المسجل والصورة الجديدة، أو أرسل طلب تحديث بياناتك. الإدارة ستراجع الصورة وتستبدلها في الشجرة بعد الاعتماد.", link: "/support", linkLabel: "إرسال الصورة للإدارة" };
  }

  if (hasAny("الية عمل الموقع", "آلية عمل الموقع", "كيف يعمل الموقع", "الموقع بيشتغل ازاي", "طريقة عمل الموقع", "شرح الموقع", "كيفية استخدام الموقع", "كيف استخدم الموقع", "استخدم الموقع ازاي", "فكرة الموقع", "ايش فكرة الموقع", "وش فكرة الموقع")) {
    return {
      answer: "آلية عمل الموقع باختصار:\n1- يعرض شجرة العائلة بشكل تفاعلي يمكن البحث والتنقل فيها.\n2- يتيح للزائر معرفة صلة القرابة بين شخصين من داخل الشجرة.\n3- يسمح لأفراد العائلة بإرسال بياناتهم وصورتهم وبيانات الأب والأم للمراجعة.\n4- الإدارة تراجع الطلب ثم توافق أو ترفض مع سبب.\n5- عند الموافقة يظهر الشخص داخل الشجرة.\n6- الموقع يحتوي كذلك على صفحة النبذة، الأخبار، السير الذاتية، ومشجرة العائلة PDF."
    };
  }

  if (hasAny("من يدير الموقع", "مين يدير الموقع", "مين المسؤول", "المسؤول عن الموقع", "ادارة الموقع", "إدارة الموقع", "مين ماسك الموقع")) {
    return {
      answer: "الموقع تديره إدارة العائلة أو المسؤولون المصرح لهم داخل لوحة الإدارة. هم من يراجعون طلبات إضافة الأفراد، يحدثون البيانات، ينشرون الأخبار، ويديرون السير الذاتية والصفحات العامة."
    };
  }

  if (hasAny("كيف نتواصل مع ادارة الموقع", "كيف نتواصل مع إدارة الموقع", "اتواصل مع الادارة", "تواصل مع الادارة", "اكلم الادارة", "ازاي اكلم الادارة", "كيف ارسل رسالة", "الدعم", "رسائل الدعم", "تواصل معنا")) {
    return {
      answer: "تقدر تتواصل مع إدارة الموقع من خلال صفحة تواصل معنا / الدعم الموجودة في الموقع. اكتب رسالتك وبيانات التواصل المتاحة، وستصل للإدارة لمراجعتها والرد عليها حسب الآلية المعتمدة.",
      link: "/support",
      linkLabel: "فتح صفحة التواصل"
    };
  }

  if (hasAny("كيف اضيف بياناتي", "كيف أضيف بياناتي", "اضيف بياناتي", "إضافة بياناتي", "ابغى اضيف اسمي", "ابي اضيف اسمي", "عايز اضيف نفسي", "ازاي اضيف نفسي", "ارسال بيانات", "طلب اضافة فرد")) {
    return {
      answer: "لإضافة بياناتك افتح صفحة إضافة بياناتك، املأ البيانات المطلوبة مثل الاسم، الصورة، الأب والأم، تاريخ الميلاد، المستوى التعليمي، وأي معلومات متاحة، ثم اضغط إرسال للمراجعة. سيظهر لك رقم مرجعي احتفظ به لتتبع الطلب.",
      link: "/submit-person",
      linkLabel: "إضافة بياناتك"
    };
  }

  if (hasAny("كيف اتابع طلبي", "كيف أتابع طلبي", "تتبع الطلب", "متابعة الطلب", "رقم مرجعي", "الرقم المرجعي", "فين طلبي", "حالة الطلب")) {
    return {
      answer: "لتتبع طلبك افتح صفحة إضافة بياناتك، ثم انزل إلى قسم تتبع الطلب واكتب الرقم المرجعي الذي ظهر لك بعد الإرسال. ستظهر الحالة: قيد المراجعة، تمت الموافقة، أو تم الرفض مع السبب.",
      link: "/submit-person#track-request",
      linkLabel: "تتبع الطلب"
    };
  }

  if (hasAny("ليه اسمي ما ظهر", "لماذا لا يظهر اسمي", "اسمي ماظهر", "اسمي لم يظهر", "متى يظهر اسمي", "ليه البيانات ما ظهرت", "لم تظهر بياناتي")) {
    return {
      answer: "الاسم لا يظهر مباشرة بعد الإرسال لأن الإدارة تراجع الطلب أولًا للحفاظ على دقة بيانات العائلة. بعد الموافقة يظهر الفرد داخل الشجرة، وإذا تم الرفض يظهر سبب الرفض عند تتبع الطلب بالرقم المرجعي."
    };
  }

  if (hasAny("هل رقم الجوال يظهر", "هل الايميل يظهر", "هل العنوان يظهر", "خصوصية", "البيانات الخاصة", "رقم الجوال للعامة", "البريد للعامة", "العنوان للعامة")) {
    return {
      answer: "لا، البيانات الخاصة مثل رقم الجوال والبريد الإلكتروني والعنوان مخصصة للإدارة فقط ولا تظهر للعامة، حفاظًا على خصوصية أفراد العائلة."
    };
  }

  if (hasAny("صلة القرابة", "صله القرابه", "معرفة صلة", "هذا قريبي", "هذه قريبي", "احسب القرابة", "اعرف القرابة")) {
    return {
      answer: "أقدر أحسب صلة القرابة مباشرة لو كتبت اسمين واضحين. مثال: ما صلة القرابة بين فلان بن فلان وفلان بن فلان؟ كما يمكنك استخدام صفحة صلة القرابة لإدخال الاسمين يدويًا.",
      link: "/kinship",
      linkLabel: "فتح صفحة صلة القرابة"
    };
  }

  if (hasAny("الشجرة", "شجرة العائلة", "الشجرة التفاعلية", "ابحث في الشجرة", "موقع الشخص في الشجرة", "مكانه في الشجرة")) {
    return {
      answer: "الشجرة التفاعلية تعرض أفراد العائلة وروابط الأبناء والآباء. يمكنك البحث عن الشخص بالاسم، أو اسألني باسم الشخص وسأعرض بياناته وروابط موقعه في الشجرة إن كان مسجلًا.",
      link: "/",
      linkLabel: "فتح الشجرة"
    };
  }

  if (hasAny("السير الذاتية", "السيرة الذاتية", "النبذة", "النبذه", "التكريم", "الشخصيات", "اعلام العائلة")) {
    return {
      answer: "صفحة السير الذاتية تعرض نبذات وصور وتفاصيل عن بعض أفراد العائلة أو الشخصيات المضافة من الإدارة. يمكنك فتح الصفحة أو سؤالي عن اسم شخص محدد داخل الشجرة.",
      link: "/honor",
      linkLabel: "فتح السير الذاتية"
    };
  }

  if (hasAny("اخبار", "أخبار", "المناسبات", "الأخبار", "آخر خبر", "اخر خبر", "جديد العائلة")) {
    return null;
  }

  if (hasAny("مشجرة", "pdf", "بي دي اف", "تحميل الشجرة", "ملف الشجرة")) {
    return {
      answer: "صفحة المشجرة تعرض ملف الشجرة أو نسخة PDF إن كانت الإدارة قد أضافتها. يمكنك فتحها من رابط مشجرة العائلة.",
      link: "/treepdf",
      linkLabel: "فتح مشجرة العائلة"
    };
  }

  if (hasAny("رمضان", "شوال", "محرم", "صفر", "ربيع", "رجب", "شعبان", "ذو القعدة", "ذو الحجة", "اكتوبر", "أكتوبر", "نوفمبر", "ديسمبر", "يناير", "فبراير", "مارس", "ابريل", "أبريل", "مايو", "يونيو", "يوليو", "اغسطس", "أغسطس", "سبتمبر")) {
    const countdown = detectMonthCountdown(q);
    if (countdown) return countdown;
  }

  if (hasAny("شكرا", "شكر", "تسلم", "يعطيك العافيه", "يعطيك العافية", "ما قصرت", "جزاك الله خير", "الله يوفقك", "تمام", "حلو", "خلاص شكرا", "مع السلامة")) {
    return pickSaudiResponse([
      "العفو، حيّاك الله في أي وقت.",
      "الله يعافيك، سعدت بخدمتك.",
      "ما سوّينا إلا الواجب، تفضل بأي وقت.",
      "وإياك يا رب، تحت أمرك.",
      "تمام، أي خدمة ثانية أنا حاضر."
    ]);
  }

  return null;
}


/* =========================
   Saud assistant uploaded command dictionary expansion
   Covers all commands from the latest supplied dictionary plus designer variants.
   ========================= */
const SAUD_UPLOADED_COMMANDS = [
  {
    "q": "اكتب خبر عن مولود جديد",
    "a": "رزق [اسم الأب] بمولود جديد أسماه [اسم المولود]، سائلين الله أن يجعله من مواليد السعادة، وأن يقرّ به عين والديه، وأن ينبته نباتًا حسنًا."
  },
  {
    "q": "اكتب خبر عن زواج",
    "a": "احتفلت أسرة خاشقجي بزواج [اسم العريس] على كريمة [اسم العائلة/الأب]، في أجواء مفعمة بالفرح والسرور، سائلين الله أن يبارك لهما ويجمع بينهما في خير."
  },
  {
    "q": "اكتب خبر عن خطوبة",
    "a": "تتقدم أسرة خاشقجي بالتهنئة إلى [اسم الشخص] بمناسبة الخطوبة، سائلين الله أن يتمم لهما على خير، وأن يكتب لهما السعادة والتوفيق."
  },
  {
    "q": "اكتب خبر عن تخرج",
    "a": "تتقدم أسرة خاشقجي بأجمل التهاني إلى [اسم الخريج] بمناسبة تخرجه، سائلين الله له دوام النجاح والتوفيق في حياته العلمية والعملية."
  },
  {
    "q": "اكتب خبر عن ترقية",
    "a": "تبارك أسرة خاشقجي لـ [الاسم] بمناسبة ترقيته إلى [المنصب]، متمنين له مزيدًا من التقدم والنجاح."
  },
  {
    "q": "اكتب خبر عن تكريم أحد أفراد الأسرة",
    "a": "تم تكريم [الاسم] تقديرًا لجهوده وإنجازاته، وتفخر أسرة خاشقجي بهذا التميز المشرف، سائلين الله له دوام التوفيق."
  },
  {
    "q": "اكتب خبر عن اجتماع عائلي",
    "a": "أقيم اجتماع عائلي جمع عددًا من أفراد أسرة خاشقجي في أجواء من المحبة وصلة الرحم، تأكيدًا على روح الترابط والتواصل بين أفراد الأسرة."
  },
  {
    "q": "اكتب خبر عن زيارة عائلية",
    "a": "في أجواء يسودها الود والمحبة، تمت زيارة عائلية جمعت عددًا من أفراد أسرة خاشقجي، تأكيدًا على روابط القربى وصلة الرحم."
  },
  {
    "q": "اكتب خبر عن افتتاح موقع أسرة خاشقجي",
    "a": "تم بحمد الله إطلاق موقع أسرة خاشقجي، ليكون منصة عائلية تجمع أفراد الأسرة، وتوثق أخبارهم ومناسباتهم، وتحفظ شجرة العائلة بروح عصرية ومنظمة."
  },
  {
    "q": "اكتب خبر عن مناسبة سعيدة",
    "a": "شاركت أسرة خاشقجي فرحة [اسم المناسبة] في أجواء عائلية جميلة، سائلين الله أن يديم الأفراح والمسرات على الجميع."
  },
  {
    "q": "اكتب خبر عن نجاح أحد أفراد الأسرة",
    "a": "تبارك أسرة خاشقجي لـ [الاسم] بمناسبة نجاحه، متمنين له مستقبلًا مشرقًا ومزيدًا من التفوق والإنجاز."
  },
  {
    "q": "اكتب خبر عن عودة أحد أفراد الأسرة من السفر",
    "a": "عاد بحمد الله [الاسم] من السفر سالمًا، ونسأل الله أن يجعل عودته مباركة وأن يديم عليه الصحة والعافية."
  },
  {
    "q": "اكتب خبر عن حفل عائلي",
    "a": "أقيم حفل عائلي جمع أفراد أسرة خاشقجي في أجواء من الفرح والبهجة، وسط حضور الأهل والأحباب."
  },
  {
    "q": "اكتب خبر عن إنجاز شخص من الأسرة",
    "a": "تفخر أسرة خاشقجي بإنجاز [الاسم] في مجال [المجال]، سائلين الله له دوام التوفيق والنجاح."
  },
  {
    "q": "اكتب خبر وفاة بصيغة محترمة",
    "a": "بقلوب مؤمنة بقضاء الله وقدره، تنعى أسرة خاشقجي فقيدها [اسم المتوفى]، سائلين الله أن يتغمده بواسع رحمته، وأن يسكنه فسيح جناته، ويلهم أهله وذويه الصبر والسلوان."
  },
  {
    "q": "اكتب تهنئة بمولود جديد",
    "a": "نبارك لكم قدوم المولود الجديد [اسم المولود]، ونسأل الله أن يجعله من مواليد السعادة، وأن يقرّ به أعين والديه."
  },
  {
    "q": "اكتب تهنئة زواج رسمية",
    "a": "نبارك لـ [اسم العريس] زواجه المبارك، ونسأل الله أن يبارك لهما ويبارك عليهما ويجمع بينهما في خير."
  },
  {
    "q": "اكتب تهنئة تخرج قصيرة",
    "a": "ألف مبروك التخرج يا [الاسم]، ومنها للأعلى بإذن الله، ونسأل الله لك مستقبلًا مليئًا بالنجاح."
  },
  {
    "q": "اكتب تهنئة عيد الفطر",
    "a": "تتقدم أسرة خاشقجي بأجمل التهاني بمناسبة عيد الفطر المبارك، أعاده الله علينا وعليكم بالخير واليمن والبركات."
  },
  {
    "q": "اكتب تهنئة عيد الأضحى",
    "a": "كل عام وأنتم بخير بمناسبة عيد الأضحى المبارك، ونسأل الله أن يعيده على أسرة خاشقجي والأمة الإسلامية بالخير والبركة."
  },
  {
    "q": "اكتب تهنئة رمضان",
    "a": "مبارك عليكم شهر رمضان المبارك، ونسأل الله أن يعيننا وإياكم على الصيام والقيام وصالح الأعمال."
  },
  {
    "q": "اكتب تهنئة بالترقية",
    "a": "نبارك لـ [الاسم] هذه الترقية المستحقة، ونسأل الله أن يجعلها عونًا له على الخير ومزيدًا من النجاح."
  },
  {
    "q": "اكتب تهنئة بالنجاح",
    "a": "ألف مبروك النجاح يا [الاسم]، فرحتنا بك كبيرة، ونسأل الله أن يوفقك دائمًا لما يحب ويرضى."
  },
  {
    "q": "اكتب تهنئة افتتاح الموقع",
    "a": "نبارك افتتاح موقع أسرة خاشقجي، ونسأل الله أن يكون منصة نافعة تجمع الأسرة وتحفظ تاريخها ومناسباتها."
  },
  {
    "q": "اكتب رسالة مباركة للعائلة",
    "a": "نبارك لأسرة خاشقجي هذه المناسبة السعيدة، ونسأل الله أن يديم الأفراح والمحبة والترابط بين الجميع."
  },
  {
    "q": "اكتب تعزية رسمية",
    "a": "بقلوب مؤمنة بقضاء الله وقدره، نتقدم بخالص العزاء والمواساة في وفاة [اسم المتوفى]، سائلين الله أن يغفر له ويرحمه ويسكنه فسيح جناته."
  },
  {
    "q": "اكتب تعزية قصيرة للواتساب",
    "a": "عظم الله أجركم، وأحسن عزاءكم، وغفر لميتكم، وأسكنه فسيح جناته."
  },
  {
    "q": "اكتب دعاء للمتوفى",
    "a": "اللهم اغفر له وارحمه، وعافه واعف عنه، وأكرم نزله، ووسّع مدخله، واجعل قبره روضة من رياض الجنة."
  },
  {
    "q": "اكتب رد على رسالة تعزية",
    "a": "شكر الله سعيكم، وجزاكم الله خيرًا، ولا أراكم الله مكروهًا في عزيز."
  },
  {
    "q": "اكتب إعلان عزاء باسم الأسرة",
    "a": "تتقدم أسرة خاشقجي بخالص العزاء والمواساة لذوي الفقيد [اسم المتوفى]، سائلين الله أن يتغمده بواسع رحمته، وأن يلهم أهله الصبر والسلوان."
  },
  {
    "q": "اكتب قصيدة عن أسرة خاشقجي",
    "a": "يا خاشقجي يا اسم عزٍ ومقدار، يا رمز طيبٍ بالوفا دوم مذكور، تاريخكم نورٍ على كل الأقطار، ومجدكم باقي على مر العصور."
  },
  {
    "q": "اكتب قصيدة فخر عائلية",
    "a": "حنا عيال المجد والطيب عنوان، نسلٍ تربّى عالوفا والمروّة، تاريخنا عالي وله قدر ومكان، واسم العائلة يبقى رمز قوة."
  },
  {
    "q": "اكتب بيت شعر ترحيبي",
    "a": "يا مرحبا باللي حضر بين الأحباب، نورت دارٍ بالوفا دوم عامرة."
  },
  {
    "q": "اكتب قصيدة عن لمّة العائلة",
    "a": "يا زين لمّة أهلنا في محبة، قلوبٍ على الطيب والوفا تجتمع، قرب القرايب نعمةٍ مستحبة، وبنورهم كل الحزن ينقشع."
  },
  {
    "q": "اكتب قصيدة عن الجد",
    "a": "يا جدنا يا أصل فخر ومهابة، ذكرك على روس المعالي مقام، منك الوفا والطيب وأحلى كتابة، ومنك تعلمنا المراجل تمام."
  },
  {
    "q": "اكتب قصيدة زواج",
    "a": "يا عريس الخير يا بدر التمام، نبارك لك فرحة العمر السعيدة، جعل أيامك محبة وسلام، وحياتك بالهنا دوم مديدة."
  },
  {
    "q": "اكتب قصيدة تخرج",
    "a": "رفعت راس أهلك بطيب الإنجاز، واليوم نفرح بك ونفخر بممشاك، يا جعل دربك للمفاخر والأعزاز، والنجاح دوم رفيقك بمسعاك."
  },
  {
    "q": "اكتب قصيدة عن صلة الرحم",
    "a": "صلة الرحم نورٍ يضوي دروبنا، ومن جمع الأهل عاش بعز وسعادة، قرب القرايب راحةٍ في قلوبنا، وطيب التواصل مكرمة وعبادة."
  },
  {
    "q": "اكتب أبيات قصيرة عن العائلة",
    "a": "يا عزوتي يا فخر الأيام، بكم تحلى سنيني، أنتم هل الطيب والأنعام، وأنتم نور عيني."
  },
  {
    "q": "اكتب قصيدة افتتاح الموقع",
    "a": "افتحوا باب الوفا باسم الجماعة، واجمعوا تاريخنا بين السطور، موقعٍ يحفظ لنا أصل ومكانة، ويجمع الأحباب في أحلى حضور."
  },
  {
    "q": "احسب 15% من 2000",
    "a": "15% من 2000 تساوي 300."
  },
  {
    "q": "احسب الضريبة 15% على 500 ريال",
    "a": "قيمة الضريبة 75 ريال، والإجمالي بعد إضافة الضريبة 575 ريال."
  },
  {
    "q": "احسب المبلغ بعد خصم 20%",
    "a": "إذا كان المبلغ [المبلغ] والخصم 20%، فالخصم يساوي [المبلغ × 0.20]، والمبلغ بعد الخصم يساوي [المبلغ - قيمة الخصم]."
  },
  {
    "q": "قسم 1200 ريال على 4 أشخاص",
    "a": "نصيب كل شخص هو 300 ريال."
  },
  {
    "q": "احسب عمر شخص مولود سنة 1990",
    "a": "إذا كنا في عام 2026، فعمر الشخص تقريبًا 36 سنة."
  },
  {
    "q": "كم سنة بين 1980 و2026؟",
    "a": "الفرق بين 1980 و2026 هو 46 سنة."
  },
  {
    "q": "احسب عدد الطاولات إذا الحضور 150 وكل طاولة 10 أشخاص",
    "a": "تحتاجون 15 طاولة، لأن 150 ÷ 10 = 15."
  },
  {
    "q": "احسب تكلفة مناسبة إذا الشخص بـ 120 ريال وعدد الحضور 80",
    "a": "التكلفة الإجمالية 9600 ريال، لأن 120 × 80 = 9600."
  },
  {
    "q": "احسب المتوسط بين 80 و90 و70",
    "a": "المتوسط هو 80، لأن مجموع الأرقام 240، و240 ÷ 3 = 80."
  },
  {
    "q": "احسب الباقي من 1000 بعد دفع 350",
    "a": "الباقي هو 650."
  },
  {
    "q": "صحح هذا النص",
    "a": "أبشر، أرسل النص وسأصححه لك لغويًا مع الحفاظ على المعنى."
  },
  {
    "q": "أعد صياغة هذا الخبر",
    "a": "أرسل نص الخبر، وسأعيد صياغته بأسلوب واضح ومناسب للنشر."
  },
  {
    "q": "خليه رسمي",
    "a": "حاضر، سأعيد صياغة النص بأسلوب رسمي ومرتب."
  },
  {
    "q": "خليه باللهجة السعودية",
    "a": "أبشر، سأعيد كتابته بلهجة سعودية واضحة ومناسبة."
  },
  {
    "q": "خليه مختصر",
    "a": "حاضر، سأختصر النص مع الحفاظ على المعنى الأساسي."
  },
  {
    "q": "خليه مناسب للنشر في الموقع",
    "a": "أبشر، سأجعله بصياغة مرتبة ورسمية مناسبة للنشر في موقع أسرة خاشقجي."
  },
  {
    "q": "خليه مناسب للواتساب",
    "a": "حاضر، سأجعله مختصرًا وواضحًا ومناسبًا للإرسال عبر واتساب."
  },
  {
    "q": "اكتب عنوان جذاب لهذا الخبر",
    "a": "أرسل نص الخبر، وسأقترح لك عنوانًا واضحًا وجذابًا يناسب النشر."
  },
  {
    "q": "اكتب وصف مختصر لهذا الخبر",
    "a": "أرسل الخبر، وسأكتب لك وصفًا مختصرًا يعبر عنه بشكل مناسب."
  },
  {
    "q": "حول النص إلى نقاط",
    "a": "أبشر، أرسل النص وسأرتبه لك على شكل نقاط واضحة."
  },
  {
    "q": "كيف أبحث عن شخص في شجرة العائلة؟",
    "a": "يمكنك البحث عن الشخص من خلال خانة البحث داخل شجرة العائلة، بكتابة الاسم كاملًا أو جزء منه."
  },
  {
    "q": "كيف أضيف فرد جديد؟",
    "a": "إذا كانت لديك صلاحية، يمكنك إضافة فرد جديد من لوحة التحكم. وإذا لم تكن لديك صلاحية، يمكنك إرسال البيانات للإدارة لمراجعتها."
  },
  {
    "q": "كيف أعدل بيانات شخص؟",
    "a": "يمكن تعديل البيانات من خلال صفحة الشخص إذا كانت لديك صلاحية، أو إرسال طلب تعديل للإدارة."
  },
  {
    "q": "كيف أبلغ عن خطأ في الاسم؟",
    "a": "أرسل الاسم الحالي والاسم الصحيح، وسيتم مراجعة الطلب من الإدارة قبل التعديل."
  },
  {
    "q": "كيف أضيف مولود جديد في الشجرة؟",
    "a": "أرسل اسم المولود، اسم الأب، تاريخ الميلاد إن وجد، وأي بيانات إضافية، ليتم مراجعتها وإضافتها."
  },
  {
    "q": "كيف أضيف مناسبة؟",
    "a": "يمكنك إرسال عنوان المناسبة، التاريخ، المكان، والوصف، وسيتم نشرها بعد المراجعة حسب سياسة الموقع."
  },
  {
    "q": "أين أجد أخبار الأسرة؟",
    "a": "يمكنك العثور على أخبار الأسرة من قسم الأخبار في الموقع أو من الصفحة الرئيسية إذا كانت الأخبار مضافة هناك."
  },
  {
    "q": "كيف أرسل خبر للإدارة؟",
    "a": "أرسل نص الخبر مع الاسم والتفاصيل والصورة إن وجدت، وسيتم مراجعته من الإدارة قبل النشر."
  },
  {
    "q": "لماذا لا تظهر بعض البيانات؟",
    "a": "حفاظًا على الخصوصية، بعض البيانات لا تظهر إلا للإدارة أو للأعضاء أصحاب الصلاحية."
  },
  {
    "q": "كيف أحافظ على خصوصية بياناتي؟",
    "a": "يمكنك عدم مشاركة بياناتك الحساسة، وطلب إخفاء بعض المعلومات من الإدارة إذا كانت ظاهرة للعامة."
  },
  {
    "q": "يا سعود ساعدني",
    "a": "أبشر، اكتب لي طلبك بوضوح، وسأساعدك خطوة بخطوة."
  },
  {
    "q": "يا سعود اشرح لي هذا النص",
    "a": "أرسل النص، وسأشرحه لك بطريقة سهلة وواضحة."
  },
  {
    "q": "يا سعود لخص لي هذا الكلام",
    "a": "أرسل الكلام، وسألخصه لك في نقاط مختصرة."
  },
  {
    "q": "يا سعود ترجم للإنجليزي",
    "a": "أرسل النص العربي، وسأترجمه لك إلى الإنجليزية."
  },
  {
    "q": "يا سعود ترجم للعربي",
    "a": "أرسل النص الإنجليزي، وسأترجمه لك إلى العربية."
  },
  {
    "q": "يا سعود اكتب رسالة رسمية",
    "a": "أبشر، اكتب لي موضوع الرسالة والجهة المرسلة إليها، وسأصيغها لك."
  },
  {
    "q": "يا سعود اكتب منشور عائلي",
    "a": "حاضر، أرسل المناسبة أو الفكرة، وسأكتب لك منشورًا مناسبًا للأسرة."
  },
  {
    "q": "يا سعود اقترح أفكار للموقع",
    "a": "أقترح إضافة أقسام مثل: المناسبات، ألبوم الصور، إنجازات أفراد الأسرة، أرشيف الأخبار، والتنبيهات العائلية."
  },
  {
    "q": "يا سعود اكتب دعوة لحضور مناسبة",
    "a": "تتشرف أسرة خاشقجي بدعوتكم لحضور [اسم المناسبة]، وذلك في يوم [اليوم] الموافق [التاريخ]، في [المكان]. حضوركم يسعدنا ويزيد المناسبة شرفًا."
  },
  {
    "q": "يا سعود اكتب رسالة شكر للحضور",
    "a": "تتقدم أسرة خاشقجي بخالص الشكر والتقدير لكل من حضر وشاركنا هذه المناسبة، فقد كان لحضوركم أثر جميل زاد فرحتنا وبهجتنا."
  },
  {
    "q": "اكتب نبذة عن أسرة خاشقجي",
    "a": "أسرة خاشقجي من الأسر العريقة التي يحرص أفرادها على الترابط وصلة الرحم وحفظ التاريخ العائلي، ويأتي هذا الموقع ليكون منصة تجمع أخبار الأسرة ومناسباتها وشجرة العائلة."
  },
  {
    "q": "اكتب رسالة ترحيب لزوار الموقع",
    "a": "أهلًا وسهلًا بكم في موقع أسرة خاشقجي، منصة تجمع أفراد الأسرة على المحبة، وتوثق الأخبار والمناسبات، وتحفظ الروابط العائلية."
  },
  {
    "q": "اكتب وصف لقسم شجرة العائلة",
    "a": "يتيح قسم شجرة العائلة استعراض الروابط العائلية بين أفراد أسرة خاشقجي بطريقة منظمة وواضحة، مع الحفاظ على خصوصية البيانات."
  },
  {
    "q": "اكتب وصف لقسم الأخبار",
    "a": "يعرض قسم الأخبار آخر المستجدات والمناسبات الخاصة بأسرة خاشقجي، من تهاني وإنجازات واجتماعات وأحداث عائلية."
  },
  {
    "q": "اكتب وصف لقسم المناسبات",
    "a": "يضم قسم المناسبات أهم المناسبات العائلية، مثل الزواج، التخرج، المواليد، الاجتماعات، والتهاني العامة."
  },
  {
    "q": "اكتب رسالة عند عدم وجود نتائج بحث",
    "a": "لم يتم العثور على نتائج مطابقة. يرجى تجربة كتابة الاسم بطريقة مختلفة أو استخدام جزء من الاسم."
  },
  {
    "q": "اكتب رسالة خطأ عامة",
    "a": "نعتذر، حدث خطأ غير متوقع. يرجى المحاولة مرة أخرى أو التواصل مع إدارة الموقع إذا استمرت المشكلة."
  },
  {
    "q": "اكتب رسالة نجاح الإرسال",
    "a": "تم إرسال طلبك بنجاح، وسيتم مراجعته من الإدارة في أقرب وقت."
  },
  {
    "q": "اكتب رسالة رفض تعديل",
    "a": "نعتذر، لم يتم اعتماد التعديل لعدم اكتمال البيانات أو لعدم توفر ما يثبت صحة المعلومة."
  },
  {
    "q": "اكتب رسالة قبول تعديل",
    "a": "تم اعتماد التعديل بنجاح بعد مراجعته من الإدارة. نشكر لكم تعاونكم في تحديث بيانات الأسرة."
  },
  {
    "q": "أبغى أكتب خبر مولود باسم أحمد",
    "a": "أبشر، هذه صيغة مناسبة: رزق [اسم الأب] بمولود جديد أسماه أحمد، نسأل الله أن يجعله من مواليد السعادة وأن يقرّ به عين والديه."
  },
  {
    "q": "اكتب خبر زواج قصير",
    "a": "نبارك لـ [اسم العريس] زواجه المبارك، ونسأل الله أن يبارك لهما ويجمع بينهما في خير."
  },
  {
    "q": "اكتب تهنئة تخرج باسم خالد",
    "a": "نبارك لـ خالد تخرجه، ونسأل الله له دوام التوفيق والنجاح، وأن تكون هذه البداية لمستقبل مشرق بإذن الله."
  },
  {
    "q": "اكتب تعزية مختصرة",
    "a": "عظم الله أجركم، وأحسن عزاءكم، وغفر لميتكم، وأسكنه فسيح جناته."
  },
  {
    "q": "اكتب قصيدة قصيرة عن العائلة",
    "a": "يا عزوتي يا فخر الأيام، بكم تحلى سنيني، أنتم هل الطيب والأنعام، وأنتم نور عيني."
  },
  {
    "q": "احسب تكلفة 100 شخص كل شخص 150 ريال",
    "a": "التكلفة الإجمالية 15000 ريال، لأن 100 × 150 = 15000."
  },
  {
    "q": "اكتب دعوة زواج",
    "a": "يسرنا دعوتكم لحضور حفل زواج [اسم العريس]، وذلك في يوم [اليوم] الموافق [التاريخ] في [المكان]. حضوركم شرف لنا."
  },
  {
    "q": "اكتب شكر بعد مناسبة",
    "a": "شكرًا لكل من شاركنا فرحتنا وحضر مناسبتنا، فقد زاد حضوركم الفرح جمالًا، ونسأل الله أن يديم المحبة بيننا."
  },
  {
    "q": "اكتب إعلان اجتماع عائلي",
    "a": "تعلن أسرة خاشقجي عن إقامة اجتماع عائلي في يوم [اليوم] الموافق [التاريخ]، وذلك في [المكان]، سائلين الله أن يجمعنا على المحبة وصلة الرحم."
  },
  {
    "q": "اكتب رسالة للإدارة لتعديل اسم",
    "a": "السلام عليكم، أرجو تعديل اسم [الاسم الحالي] إلى [الاسم الصحيح] في شجرة العائلة، شاكرين لكم جهودكم."
  },
  {
    "q": "مين الي صمم الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "مين اللي صمم الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من الي صمم الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من الذي صمم الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من صنع الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "مين صنع الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من عمل الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "مين عمل الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من نفذ الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من برمج الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "مين برمج الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "مين مطور الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من مطور الموقع",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "من المبرمج",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  },
  {
    "q": "مين المبرمج",
    "a": "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803."
  }
];

function saudCommandSimilarity(questionNorm, commandNorm) {
  if (!questionNorm || !commandNorm) return 0;
  if (questionNorm === commandNorm) return 100;
  if (questionNorm.includes(commandNorm)) return 98;
  if (commandNorm.includes(questionNorm) && questionNorm.length >= 6) return 88;
  const qParts = questionNorm.split(" ").filter(Boolean);
  const cParts = commandNorm.split(" ").filter(Boolean);
  if (!qParts.length || !cParts.length) return 0;
  const cSet = new Set(cParts);
  const qSet = new Set(qParts);
  let overlap = 0;
  qParts.forEach((p) => { if (cSet.has(p)) overlap++; });
  const ratioQ = overlap / qParts.length;
  const ratioC = overlap / cParts.length;
  const firstOk = qParts[0] && cSet.has(qParts[0]);
  const important = ["اكتب","احسب","صحح","ترجم","لخص","اقترح","كيف","من","مين","وش","يا","عيد","تهنئه","تعزيه","قصيده","خبر"].some(w => questionNorm.includes(w) && commandNorm.includes(w));
  let score = Math.round((ratioQ * 60) + (ratioC * 30) + (firstOk ? 5 : 0) + (important ? 5 : 0));
  return score;
}

function answerUploadedSaudCommand(question) {
  const nq = normalizeArabicForMatch(question);
  if (!nq) return null;

  const designerWords = ["صمم", "صنع", "عمل", "نفذ", "برمج", "طور", "مطور", "مصمم", "مبرمج", "مطور"].some(w => nq.includes(normalizeArabicForMatch(w)));
  const siteWords = ["الموقع", "موقع", "المنصه", "المنصة"].some(w => nq.includes(normalizeArabicForMatch(w)));
  if (designerWords && siteWords && ["من", "مين", "مينو", "مين اللي", "مين الي", "من اللي", "من الي", "من الذي"].some(w => nq.includes(normalizeArabicForMatch(w)))) {
    return { answer: "تم تصميم وتنفيذ الموقع بواسطة مهندس مصري اسمه حازم النجار. رقم التواصل: +201063718803." };
  }

  let best = null;
  let bestScore = 0;
  for (const item of SAUD_UPLOADED_COMMANDS) {
    const cn = normalizeArabicForMatch(item.q);
    const score = saudCommandSimilarity(nq, cn);
    if (score > bestScore) { best = item; bestScore = score; }
  }
  if (best && bestScore >= 82) {
    return { answer: best.a };
  }
  return null;
}

const __saudPreviousWebsiteFAQ = answerWebsiteFAQ;
answerWebsiteFAQ = function(question) {
  const uploaded = answerUploadedSaudCommand(question);
  if (uploaded) return uploaded;
  return __saudPreviousWebsiteFAQ(question);
};

const __saudPreviousGeneralKnowledge = freeGeneralKnowledgeAnswer;
freeGeneralKnowledgeAnswer = function(question) {
  const uploaded = answerUploadedSaudCommand(question);
  if (uploaded) return uploaded;
  return __saudPreviousGeneralKnowledge(question);
};

/* =========================
   Public Routes
   ========================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});


app.get("/kinship", async (req, res) => {
  try {
    const personA = cleanText(req.query.person_a || "", 220);
    const personB = cleanText(req.query.person_b || "", 220);
    const result = personA && personB ? await calculateKinshipByNames(personA, personB) : null;
    res.render("public_kinship", { slug: "kinship", personA, personB, result });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء حساب صلة القرابة");
  }
});

app.post("/api/kinship", async (req, res) => {
  try {
    const personA = cleanText(req.body?.person_a || req.body?.personA || "", 220);
    const personB = cleanText(req.body?.person_b || req.body?.personB || "", 220);
    if (!personA || !personB) return res.status(400).json({ ok:false, message:"اكتب اسم الشخصين أولًا." });
    const result = await calculateKinshipByNames(personA, personB);
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, message:"حدث خطأ أثناء حساب صلة القرابة." });
  }
});

app.post("/api/site-assistant", async (req, res) => {
  try {
    const question = req.body?.question || "";
    const siteAnswer = await answerSiteAssistant(question);
    if (siteAnswer && siteAnswer.general) {
      const generalAnswer = await answerGeneralAssistant(question);
      return res.json({ ok:true, mode:"general", ...generalAnswer });
    }
    res.json({ ok:true, mode:"site", ...siteAnswer });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, answer:"حدث خطأ أثناء تشغيل المساعد." });
  }
});

app.get("/timeline", async (req, res) => {
  try {
    const rows = await all(`SELECT * FROM timeline_events WHERE visible=1 ORDER BY "order" ASC`);
    res.render("public_page", { timeline: rows });
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error: " + err.message);
  }
});

app.get("/about", async (req, res) => {
  try {
    const page = await get(`SELECT * FROM site_pages WHERE slug='about'`);
    if (!page) return res.status(404).send("صفحة النبذة غير موجودة");

    const timeline = await getPublicTimelineItems();
    return res.render("public_page", { slug: "about", page, timeline });
  } catch (e) {
    try {
      const page = await get(`SELECT * FROM site_pages WHERE slug='about'`);
      const timeline = await getPublicTimelineItems();
      return res.render("about", { page, timeline });
    } catch (err) {
      console.error(err);
      return res.status(500).send("خطأ في تحميل صفحة النبذة");
    }
  }
});

app.get("/support", async (req, res) => {
  try {
    const page = await get(`SELECT * FROM site_pages WHERE slug='support'`);
    if (!page) return res.status(404).send("صفحة الدعم غير موجودة");

    return res.render("public_support", {
      slug: "support",
      page,
      sent: req.query.sent === "1",
    });
  } catch (e) {
    try {
      const page = await get(`SELECT * FROM site_pages WHERE slug='support'`);
      return res.render("support", { page, sent: req.query.sent === "1" });
    } catch (err) {
      console.error(err);
      return res.status(500).send("خطأ في تحميل صفحة الدعم");
    }
  }
});

app.post("/support/send", async (req, res) => {
  try {
    const { sender_name, phone, message } = req.body;
    await run(
      `INSERT INTO support_messages (sender_name, phone, message, created_at)
       VALUES (?, ?, ?, datetime('now'))`,
      [
        String(sender_name || "").trim(),
        String(phone || "").trim(),
        String(message || "").trim(),
      ]
    );
    res.redirect("/support?sent=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ أثناء إرسال الرسالة");
  }
});

app.post("/support", async (req, res) => {
  try {
    const { sender_name, phone, message } = req.body;
    if (!sender_name || !message) return res.redirect("/support");

    await run(
      `INSERT INTO support_messages (sender_name, phone, message, created_at)
       VALUES (?, ?, ?, datetime('now'))`,
      [
        String(sender_name || "").trim(),
        String(phone || "").trim(),
        String(message || "").trim(),
      ]
    );

    return res.redirect("/support?sent=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ أثناء إرسال الرسالة");
  }
});

app.get("/tree-pdf", async (req, res) => {
  try {
    const page = await get(`SELECT * FROM site_pages WHERE slug='tree-pdf'`);
    if (!page) return res.status(404).send("صفحة شجرة PDF غير موجودة");

    try {
      return res.render("public_treepdf", { slug: "tree-pdf", page });
    } catch (_) {
      return res.render("tree-pdf", { page });
    }
  } catch (e) {
    try {
      const page = await get(`SELECT * FROM site_pages WHERE slug='tree-pdf'`);
      return res.render("tree_pdf", { page });
    } catch (err) {
      console.error(err);
      return res.status(500).send("خطأ في تحميل صفحة PDF");
    }
  }
});

app.get("/honor", async (req, res) => {
  try {
    const items = await getPublicHonorItems();

    try {
      return res.render("public_honor", { slug: "honor", items });
    } catch (_) {
      return res.render("honor", { items });
    }
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل صفحة قائمة الشرف");
  }
});

app.get("/news", async (req, res) => {
  try {
    const posts = await getPublicNews(50);

    res.render("public_news", { slug: "news", posts }, (err, html) => {
      if (!err) return res.send(html);

      const cards = posts.map((p) => `
        <article style="border:1px solid #e5e7eb;border-radius:14px;padding:16px;background:#fff;margin-bottom:12px">
          ${p.image_url ? `<img src="${String(p.image_url).replace(/"/g, "&quot;")}" style="width:100%;max-height:280px;object-fit:cover;border-radius:12px;margin-bottom:12px">` : ""}
          <h2 style="margin:0 0 8px">${String(p.title || "").replace(/</g, "&lt;")}</h2>
          <p style="color:#555">${String(p.summary || p.content || "").replace(/</g, "&lt;")}</p>
          <a href="/news/${p.id}" style="display:inline-block;margin-top:10px;color:#1f637a;font-weight:bold">اقرأ المزيد</a>
        </article>
      `).join("");

      return res.send(`
        <!doctype html>
        <html lang="ar" dir="rtl">
          <head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>أخبار العائلة</title></head>
          <body style="font-family:Tahoma,Arial,sans-serif;background:#f8f8f6;margin:0;padding:24px">
            <main style="max-width:900px;margin:auto">
              <a href="/" style="display:inline-block;margin-bottom:16px">العودة للشجرة</a>
              <h1>أخبار العائلة والمناسبات</h1>
              ${cards || "<p>لا توجد أخبار منشورة حاليًا.</p>"}
            </main>
          </body>
        </html>
      `);
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل الأخبار");
  }
});

app.get("/news/:id", async (req, res) => {
  try {
    const id = req.params.id;

    await run(
      `UPDATE news_posts
       SET views_count = COALESCE(views_count, 0) + 1
       WHERE id = ?
         AND COALESCE(is_active, 1) = 1`,
      [id]
    );

    const post = await get(
      `SELECT
         n.*,
         p.name AS person_name,
         p.photo_url AS person_photo_url
       FROM news_posts n
       LEFT JOIN persons p ON p.id = n.person_id
       WHERE n.id = ?
         AND COALESCE(n.is_active, 1) = 1`,
      [id]
    );

    if (!post) return res.status(404).send("الخبر غير موجود");

    const comments = await all(
      `SELECT * FROM news_comments WHERE post_id = ? ORDER BY id DESC`,
      [id]
    );

    const likes = await get(
      `SELECT COUNT(*) as c FROM news_likes WHERE post_id = ?`,
      [id]
    );

    const relatedPosts = await getRelatedNews(id, 3);
    const shareUrl = `${req.protocol}://${req.get("host")}/news/${encodeURIComponent(id)}`;

    res.render(
      "public_news_single",
      {
        slug: "news",
        post,
        relatedPosts,
        shareUrl,
        comments,
        likes: likes?.c || 0,
      },
      (err, html) => {
        if (!err) return res.send(html);

        const img = post.image_url || post.person_photo_url || "/images/default.png";
        const esc = (v) =>
          String(v || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");

        const related = (relatedPosts || []).map((p) => `
          <article style="border:1px solid #e5e7eb;border-radius:14px;padding:14px;background:#fff;margin-top:12px">
            <h3 style="margin:0 0 8px"><a href="/news/${p.id}" style="color:#1f637a;text-decoration:none">${esc(p.title)}</a></h3>
            <p style="color:#555;margin:0">${esc(p.summary || p.content || "").slice(0, 160)}</p>
          </article>
        `).join("");

        return res.send(`
          <!doctype html>
          <html lang="ar" dir="rtl">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width,initial-scale=1">
              <title>${esc(post.title)}</title>
            </head>
            <body style="font-family:Tahoma,Arial,sans-serif;background:#f8f8f6;margin:0;padding:24px;line-height:1.9">
              <main style="max-width:900px;margin:auto">
                <a href="/news" style="display:inline-block;margin-bottom:16px">العودة للأخبار</a>
                <article style="background:#fff;border:1px solid #e5e7eb;border-radius:18px;overflow:hidden">
                  <img src="${esc(img)}" style="width:100%;max-height:420px;object-fit:contain;background:#f3f4f6;display:block" onerror="this.src='/images/default.png'">
                  <div style="padding:22px">
                    <h1 style="margin:0 0 10px">${esc(post.title)}</h1>
                    <div style="color:#666;font-size:14px;margin-bottom:18px">
                      ${esc(post.event_date || post.published_at || "")}
                      • ${Number(post.views_count || 0)} مشاهدة
                      ${Number(post.is_pinned || 0) === 1 ? " • خبر مهم" : ""}
                    </div>
                    ${post.person_id ? `<div style="color:#1f637a;font-weight:bold;margin-bottom:14px">مرتبط بـ: ${esc(post.person_name || ("#" + post.person_id))}</div>` : ""}
                    <p style="white-space:pre-line;color:#333">${esc(post.content || post.summary || "")}</p>
                    ${(post.publisher_name || post.publisher_phone) ? `<div style="margin-top:18px;padding:14px;border:1px solid #e7d49a;border-radius:14px;background:#fffaf0;color:#333;font-weight:bold">
                      ${post.publisher_name ? `<div>الناشر: ${esc(post.publisher_name)}</div>` : ""}
                      ${post.publisher_phone ? `<div>جوال الناشر: ${esc(post.publisher_phone)}</div>` : ""}
                    </div>` : ""}
                    <div style="margin-top:20px;border-top:1px solid #eee;padding-top:14px">
                      <a href="https://wa.me/?text=${encodeURIComponent(post.title + " " + shareUrl)}" style="margin-inline-end:10px">مشاركة واتساب</a>
                      <a href="https://twitter.com/intent/tweet?text=${encodeURIComponent(post.title)}&url=${encodeURIComponent(shareUrl)}" style="margin-inline-end:10px">مشاركة تويتر</a>
                      <span>${esc(shareUrl)}</span>
                    </div>
                  </div>
                </article>
                ${related ? `<h2>أخبار مشابهة</h2>${related}` : ""}
              </main>
            </body>
          </html>
        `);
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل الخبر");
  }
});

app.post("/news/:id/like", likeLimiter, async (req, res) => {
  try {
    const postId = Number(req.params.id);
    if (!postId) return res.status(400).json({ ok: false, error: "خبر غير صالح" });

    const ip = getClientIp(req);
    const existing = await get(
      `SELECT id FROM news_likes
       WHERE post_id = ?
         AND COALESCE(ip_address, '') = ?
       LIMIT 1`,
      [postId, ip]
    );

    if (!existing) {
      await run(
        `INSERT INTO news_likes (post_id, ip_address, created_at)
         VALUES (?, ?, datetime('now'))`,
        [postId, ip]
      );
    }

    const count = await get(
      `SELECT COUNT(*) as c FROM news_likes WHERE post_id = ?`,
      [postId]
    );

    res.json({ ok: true, count: count?.c || 0, alreadyLiked: !!existing });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false });
  }
});

app.post("/news/:id/comment", commentLimiter, async (req, res) => {
  try {
    const postId = Number(req.params.id);
    if (!postId) return res.redirect("/news");

    const name = cleanText(req.body.name, 80);
    const content = cleanText(req.body.content, 1000);

    if (name.length < 2 || content.length < 3) {
      return res.redirect(`/news/${postId}?comment=invalid`);
    }

    if (hasLinks(name) || hasLinks(content)) {
      return res.redirect(`/news/${postId}?comment=blocked`);
    }

    const ip = getClientIp(req);

    const recent = await get(
      `SELECT id
       FROM news_comments
       WHERE post_id = ?
         AND COALESCE(ip_address, '') = ?
         AND datetime(created_at) >= datetime('now', '-60 seconds')
       LIMIT 1`,
      [postId, ip]
    );

    if (recent) {
      return res.redirect(`/news/${postId}?comment=slow`);
    }

    await run(
      `INSERT INTO news_comments (post_id, name, content, ip_address, created_at)
       VALUES (?, ?, ?, ?, datetime('now'))`,
      [postId, name, content, ip]
    );

    res.redirect(`/news/${postId}?comment=sent`);
  } catch (e) {
    console.error(e);
    res.redirect(`/news/${req.params.id}?comment=error`);
  }
});

async function handleNewsletterSubscribe(req, res) {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const subscriberName = String(req.body.subscriber_name || req.body.name || "").trim();

    if (!isValidEmail(email)) {
      if (req.headers.accept?.includes("application/json")) {
        return res.status(400).json({ ok: false, error: "بريد إلكتروني غير صالح" });
      }
      return res.redirect((req.get("referer") || "/news") + "?subscribed=invalid");
    }

    await run(
      `INSERT INTO newsletter_subscribers (email, subscriber_name, created_at, is_active)
       VALUES (?, ?, datetime('now'), 1)
       ON CONFLICT(email) DO UPDATE SET
         subscriber_name = COALESCE(NULLIF(?, ''), subscriber_name),
         is_active = 1`,
      [email, subscriberName, subscriberName]
    );

    if (req.headers.accept?.includes("application/json")) {
      return res.json({ ok: true });
    }

    return res.redirect((req.get("referer") || "/news") + "?subscribed=1");
  } catch (e) {
    console.error(e);
    if (req.headers.accept?.includes("application/json")) {
      return res.status(500).json({ ok: false, error: "حدث خطأ أثناء الاشتراك" });
    }
    return res.redirect((req.get("referer") || "/news") + "?subscribed=error");
  }
}

app.post("/newsletter/subscribe", handleNewsletterSubscribe);
app.post("/news/subscribe", handleNewsletterSubscribe);

app.get("/pages/about.html", (req, res) => res.redirect(301, "/about"));
app.get("/pages/support.html", (req, res) => res.redirect(301, "/support"));
app.get("/pages/tree-pdf.html", (req, res) => res.redirect(301, "/tree-pdf"));
app.get("/pages/honor.html", (req, res) => res.redirect(301, "/honor"));

/* =========================
   API
   ========================= */

app.get("/api/tree", async (req, res) => {
  try {
    const rows = await all(`
      SELECT
        id, name, father_id, mother_id, birth_date, birth_place,
        death_date, death_place, is_deceased, gender, job, education_level, lineage,
        photo_url, notes, short_bio
      FROM persons
      ORDER BY id ASC
    `);
    const root = buildTree(rows);
    res.json(root || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to load tree" });
  }
});

app.get("/api/person/:id", async (req, res) => {
  try {
    const row = await get(`
      SELECT
        id, name, father_id, mother_id, birth_date, birth_place,
        death_date, death_place, is_deceased, gender, job, education_level, lineage,
        photo_url, notes, short_bio
      FROM persons
      WHERE id = ?
    `, [req.params.id]);
    if (!row) return res.status(404).json({ error: "Not found" });

    const father = row.father_id
      ? await get("SELECT id, name, photo_url FROM persons WHERE id = ?", [row.father_id])
      : null;

    const mother = row.mother_id
      ? await get("SELECT id, name, photo_url FROM persons WHERE id = ?", [row.mother_id])
      : null;

    const children = await all(
      `SELECT id, name, photo_url, gender, is_deceased
       FROM persons
       WHERE father_id = ? OR mother_id = ?
       ORDER BY id ASC`,
      [row.id, row.id]
    );

    const spouses = await getSpouseNames(row.id);

    res.json({
      ...row,
      father,
      mother,
      children,
      spouses,
      image: row.photo_url || "",
      is_deceased: Number(row.is_deceased || 0),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to load person details" });
  }
});

app.get("/api/stats", async (req, res) => {
  try {
    const stats = await getSiteStats();
    res.json({
      total: stats.total,
      males: stats.males,
      females: stats.females,
      alive: stats.alive,
      deceased: stats.deceased,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to load stats" });
  }
});

app.get("/api/news", async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit || 6), 1), 50);
    const posts = await getPublicNews(limit);
    res.json(posts);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to load news" });
  }
});

app.get("/api/news/notifications", async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit || 5), 1), 20);
    const notifications = await all(
      `SELECT
         nf.*,
         n.image_url,
         n.published_at,
         n.event_date
       FROM news_notifications nf
       LEFT JOIN news_posts n ON n.id = nf.news_id
       WHERE COALESCE(nf.is_active, 1) = 1
       ORDER BY nf.id DESC
       LIMIT ?`,
      [limit]
    );

    res.json({ ok: true, notifications });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: "Failed to load notifications" });
  }
});

app.get("/api/news/latest", async (req, res) => {
  try {
    const latest = await get(
      `SELECT id, title, summary, image_url, event_date, published_at, is_pinned, views_count
       FROM news_posts
       WHERE COALESCE(is_active, 1) = 1
       ORDER BY COALESCE(is_pinned, 0) DESC, COALESCE(NULLIF(event_date, ''), published_at, datetime('now')) DESC, id DESC
       LIMIT 1`
    );

    res.json({ ok: true, latest });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: "Failed to load latest news" });
  }
});

/* =========================
   Admin Auth
   ========================= */

function makePersonRequestReference() {
  const year = new Date().getFullYear();
  const part = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `FAM-${year}-${part}`;
}

async function createUniquePersonRequestReference() {
  for (let i = 0; i < 12; i++) {
    const code = makePersonRequestReference();
    const exists = await get(`SELECT id FROM person_requests WHERE reference_code = ?`, [code]);
    if (!exists) return code;
  }
  return `FAM-${Date.now()}-${Math.floor(Math.random() * 9999)}`;
}

async function findPersonRequestByReference(referenceCode) {
  const code = cleanText(referenceCode, 80).toUpperCase();
  if (!code) return null;
  return get(
    `SELECT pr.id, pr.reference_code, pr.name, pr.status, pr.admin_note,
            pr.created_person_id, pr.reviewed_at, pr.created_at, p.name AS created_person_name
     FROM person_requests pr
     LEFT JOIN persons p ON pr.created_person_id = p.id
     WHERE UPPER(pr.reference_code) = ?`,
    [code]
  );
}

app.get("/api/person-lineage/resolve", async (req, res) => {
  try {
    const q = cleanText(req.query.q, 220);
    const excludeId = req.query.exclude_id || null;
    const result = await resolvePersonByThreePartLineage(q, { excludeId });
    res.json({ ok: true, result });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: "خطأ في مطابقة الاسم الثلاثي" });
  }
});

app.get("/submit-person", async (req, res) => {
  try {
    const persons = await all("SELECT id, name FROM persons ORDER BY name ASC");
    const trackReference = cleanText(req.query.reference || req.query.track || "", 80);
    const trackingResult = trackReference ? await findPersonRequestByReference(trackReference) : null;
    res.render("public_person_request", {
      persons,
      submitted: req.query.submitted === "1",
      referenceCode: cleanText(req.query.ref || "", 80),
      trackReference,
      trackingResult,
      trackingSearched: Boolean(trackReference),
      error: req.query.error || "",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل نموذج إضافة البيانات");
  }
});

app.post("/submit-person", upload.single("photo_file"), async (req, res) => {
  try {
    const body = req.body || {};
    const name = cleanText(body.name, 180);
    if (!name) {
      return res.redirect("/submit-person?error=" + encodeURIComponent("اسم الفرد مطلوب"));
    }

    const spouseList = linesToCleanArray(body.spouse_names, 20, 160);
    const childrenList = linesToCleanArray(body.children_names, 40, 160);
    const photo_url = req.file ? `/uploads/${req.file.filename}` : null;
    const referenceCode = await createUniquePersonRequestReference();

    const payload = {
      name,
      gender: cleanText(body.gender, 20) || null,
      father_id: null,
      mother_id: null,
      father_lineage_name: cleanText(body.father_lineage_name, 220) || null,
      mother_lineage_name: cleanText(body.mother_lineage_name, 220) || null,
      birth_date: cleanText(body.birth_date, 40) || null,
      birth_place: cleanText(body.birth_place, 180) || null,
      death_date: cleanText(body.death_date, 40) || null,
      death_place: cleanText(body.death_place, 180) || null,
      is_deceased: Number(body.is_deceased ? 1 : 0),
      job: cleanText(body.job, 220) || null,
      education_level: cleanText(body.education_level, 120) || null,
      mobile_phone: cleanText(body.mobile_phone, 80) || null,
      personal_email: cleanText(body.personal_email, 180) || null,
      national_address: cleanText(body.national_address, 300) || null,
      photo_url,
      notes: cleanText(body.notes, 3000) || null,
      short_bio: cleanText(body.short_bio, 2000) || null,
      spouse_names: spouseList,
      children_names: childrenList,
      submitted_by_name: cleanText(body.submitted_by_name, 180) || null,
      submitted_by_phone: cleanText(body.submitted_by_phone, 80) || null,
    };

    const fatherResolved = await resolveOptionalLineageId(payload.father_lineage_name);
    const motherResolved = await resolveOptionalLineageId(payload.mother_lineage_name);
    payload.father_id = fatherResolved.id;
    payload.mother_id = motherResolved.id;
    payload.father_match_status = fatherResolved.result?.status || null;
    payload.mother_match_status = motherResolved.result?.status || null;

    await run(
      `INSERT INTO person_requests (
        reference_code, name, gender, father_id, mother_id, father_lineage_name, mother_lineage_name, birth_date, birth_place,
        death_date, death_place, is_deceased, job, education_level, mobile_phone, personal_email,
        national_address, photo_url, notes, short_bio, spouse_names, children_names,
        payload_json, status, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      [
        referenceCode,
        payload.name,
        payload.gender,
        payload.father_id,
        payload.mother_id,
        payload.father_lineage_name,
        payload.mother_lineage_name,
        payload.birth_date,
        payload.birth_place,
        payload.death_date,
        payload.death_place,
        payload.is_deceased,
        payload.job,
        payload.education_level,
        payload.mobile_phone,
        payload.personal_email,
        payload.national_address,
        payload.photo_url,
        payload.notes,
        payload.short_bio,
        JSON.stringify(spouseList),
        JSON.stringify(childrenList),
        JSON.stringify(payload),
        getClientIp(req),
        req.headers["user-agent"] || "",
      ]
    );

    return res.redirect("/submit-person?submitted=1&ref=" + encodeURIComponent(referenceCode));
  } catch (e) {
    console.error(e);
    return res.redirect("/submit-person?error=" + encodeURIComponent("حدث خطأ أثناء إرسال الطلب"));
  }
});

app.get("/track-person-request", async (req, res) => {
  try {
    const reference = cleanText(req.query.reference || "", 80);
    const query = reference ? `?reference=${encodeURIComponent(reference)}` : "";
    return res.redirect(`/submit-person${query}#track-request`);
  } catch (e) {
    console.error(e);
    return res.redirect("/submit-person#track-request");
  }
});

app.get("/admin/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/admin/login", async (req, res) => {
  try {
    await ensureAdminRoleSchema();
    const { username, password } = req.body;
    const admin = await get("SELECT * FROM admins WHERE username = ?", [username]);
    if (!admin || Number(admin.is_active) === 0) {
      await logAdminAction(req, "فشل تسجيل الدخول", "admin", username || "", { reason: "بيانات غير صحيحة أو حساب غير نشط" });
      return res.render("login", { error: "بيانات الدخول غير صحيحة" });
    }

    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) {
      await logAdminAction(req, "فشل تسجيل الدخول", "admin", username || "", { reason: "كلمة مرور غير صحيحة" });
      return res.render("login", { error: "بيانات الدخول غير صحيحة" });
    }

    req.session.admin = {
      id: admin.id,
      username: admin.username,
      person_id: admin.person_id,
      display_name: admin.display_name,
      role_title: admin.role_title || "مدير النظام",
      permissions: admin.permissions || "[]",
      is_super_admin: Number(admin.is_super_admin) === 1 ? 1 : 0,
    };
    await logAdminAction(req, "تسجيل دخول", "admin", admin.id, { username: admin.username });
    res.redirect(firstAllowedAdminPath(req.session.admin));
  } catch (e) {
    console.error(e);
    res.render("login", { error: "حدث خطأ أثناء تسجيل الدخول" });
  }
});

app.post("/admin/logout", async (req, res) => {
  await logAdminAction(req, "تسجيل خروج", "admin", req.session?.admin?.id || "", {});
  req.session.destroy(() => res.redirect("/"));
});

/* =========================
   Upload endpoint
   ========================= */
app.post("/admin/upload", isAuthed, upload.single("photo"), (req, res) => {
  if (!req.file) return res.status(400).send("No file uploaded");
  res.json({ url: "/uploads/" + req.file.filename });
});

/* =========================
   Admin: persons CRUD
   ========================= */
app.get("/admin/dashboard", isAuthed, async (req, res) => {
  try {
    const dashboard = await getFullDashboardData();
    res.render("admin_dashboard", {
      admin: req.session.admin,
      dashboard,
      parseLogDetails,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل الإحصائيات");
  }
});

app.get("/admin/activity", isAuthed, requireSuperAdmin, async (req, res) => {
  try {
    await ensureAdminEnhancements();
    const logs = await all(`SELECT * FROM admin_activity_logs ORDER BY id DESC LIMIT 250`);
    res.render("admin_activity", { admin: req.session.admin, logs, parseLogDetails });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل سجل النشاطات");
  }
});

app.get("/admin/maintenance", isAuthed, requireSuperAdmin, async (req, res) => {
  try {
    await ensureAdminEnhancements();
    const enabled = await get(`SELECT value FROM site_settings WHERE key='maintenance_enabled'`);
    const message = await get(`SELECT value FROM site_settings WHERE key='maintenance_message'`);
    res.render("admin_maintenance", {
      admin: req.session.admin,
      enabled: String(enabled?.value || "0") === "1",
      message: message?.value || "الموقع تحت الصيانة حاليًا، يرجى المحاولة لاحقًا.",
      saved: req.query.saved === "1",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل وضع الصيانة");
  }
});

app.post("/admin/maintenance", isAuthed, requireSuperAdmin, async (req, res) => {
  try {
    await ensureAdminEnhancements();
    const enabled = req.body.maintenance_enabled ? "1" : "0";
    const message = cleanText(req.body.maintenance_message, 500) || "الموقع تحت الصيانة حاليًا، يرجى المحاولة لاحقًا.";
    await run(`UPDATE site_settings SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key='maintenance_enabled'`, [enabled]);
    await run(`UPDATE site_settings SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key='maintenance_message'`, [message]);
    await logAdminAction(req, enabled === "1" ? "تفعيل وضع الصيانة" : "إيقاف وضع الصيانة", "site_settings", "maintenance", { message });
    res.redirect("/admin/maintenance?saved=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حفظ وضع الصيانة");
  }
});

app.get("/admin", isAuthed, async (req, res) => {
  if (!userCan(req.session.admin, "persons")) return res.redirect(firstAllowedAdminPath(req.session.admin));
  try {
    const persons = await all(`
      SELECT
        p.*,
        f.name AS father_name,
        m.name AS mother_name,
        (
          SELECT group_concat(spouse_name, ' | ')
          FROM person_spouses
          WHERE person_id = p.id
          ORDER BY ord ASC, id ASC
        ) AS spouses_text
      FROM persons p
      LEFT JOIN persons f ON p.father_id = f.id
      LEFT JOIN persons m ON p.mother_id = m.id
      ORDER BY p.id ASC
    `);

    const stats = await getSiteStats();

    res.render("admin", {
      persons,
      stats,
      admin: req.session.admin,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل لوحة الإدارة");
  }
});

app.get("/admin/person-stats", isAuthed, requirePermission("persons"), async (req, res) => {
  try {
    const personStats = await getPersonStatsPageData();

    res.render("person_stats", {
      admin: req.session.admin,
      personStats,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل إحصائيات الأفراد");
  }
});

app.get("/admin/news/stats", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    const newsStats = await getNewsStatsPageData();

    res.render("news_stats", {
      admin: req.session.admin,
      newsStats,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل إحصائيات الأخبار");
  }
});

app.get("/admin/person/new", isAuthed, requirePermission("persons"), async (req, res) => {
  try {
    res.render("person_form", {
      mode: "new",
      persons: [],
      person: null,
      spouseNames: [],
      fatherLineageName: "",
      motherLineageName: "",
      admin: req.session.admin,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في فتح نموذج الإضافة");
  }
});

app.post("/admin/person/new", isAuthed, requirePermission("persons"), async (req, res) => {
  try {
    const {
      name,
      father_id,
      mother_id,
      father_lineage_name,
      mother_lineage_name,
      birth_date,
      birth_place,
      death_date,
      death_place,
      is_deceased,
      gender,
      job,
      education_level,
      mobile_phone,
      personal_email,
      national_address,
      photo_url,
      notes,
      short_bio,
    } = req.body;

    const spouse_names = req.body.spouse_names;
    const resolvedFather = await resolveOptionalLineageId(father_lineage_name);
    const resolvedMother = await resolveOptionalLineageId(mother_lineage_name);
    if (cleanText(father_lineage_name, 220) && !resolvedFather.id) {
      return res.status(400).send(resolvedFather.result?.message || "لم يتم العثور على الأب بهذا التسلسل الثلاثي");
    }

    const result = await run(
      `INSERT INTO persons (
        name, father_id, mother_id, birth_date, birth_place,
        death_date, death_place, is_deceased, gender,
        job, education_level, mobile_phone, personal_email, national_address, lineage, photo_url, notes, short_bio
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        String(name || "").trim(),
        resolvedFather.id || null,
        resolvedMother.id || null,
        birth_date || null,
        birth_place || null,
        death_date || null,
        death_place || null,
        Number(is_deceased ? 1 : 0),
        gender || null,
        job || null,
        education_level || null,
        mobile_phone || null,
        personal_email || null,
        national_address || null,
        null,
        photo_url || null,
        notes || null,
        short_bio || null,
      ]
    );

    await setSpouseNames(result.lastID, spouse_names);
    await logAdminAction(req, "إضافة فرد", "person", result.lastID, { name });
    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في إضافة الشخص");
  }
});

app.get("/admin/person/:id/edit", isAuthed, requirePermission("persons"), async (req, res) => {
  try {
    const person = await get("SELECT * FROM persons WHERE id = ?", [req.params.id]);
    if (!person) return res.redirect("/admin");

    const spouseRows = await getSpouseNames(person.id);
    const spouseNames = spouseRows.map((x) => x.spouse_name);
    const fatherLineageName = await lineageLabelForPersonId(person.father_id);
    const motherLineageName = await lineageLabelForPersonId(person.mother_id);

    res.render("person_form", {
      mode: "edit",
      persons: [],
      person,
      spouseNames,
      fatherLineageName,
      motherLineageName,
      admin: req.session.admin,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في فتح نموذج التعديل");
  }
});

app.post("/admin/person/:id/edit", isAuthed, requirePermission("persons"), async (req, res) => {
  try {
    const {
      name,
      father_id,
      mother_id,
      father_lineage_name,
      mother_lineage_name,
      birth_date,
      birth_place,
      death_date,
      death_place,
      is_deceased,
      gender,
      job,
      education_level,
      mobile_phone,
      personal_email,
      national_address,
      photo_url,
      notes,
      short_bio,
    } = req.body;

    const spouse_names = req.body.spouse_names;
    const resolvedFather = await resolveOptionalLineageId(father_lineage_name, { excludeId: req.params.id });
    const resolvedMother = await resolveOptionalLineageId(mother_lineage_name, { excludeId: req.params.id });
    if (cleanText(father_lineage_name, 220) && !resolvedFather.id) {
      return res.status(400).send(resolvedFather.result?.message || "لم يتم العثور على الأب بهذا التسلسل الثلاثي");
    }

    await run(
      `UPDATE persons
       SET
         name = ?,
         father_id = ?,
         mother_id = ?,
         birth_date = ?,
         birth_place = ?,
         death_date = ?,
         death_place = ?,
         is_deceased = ?,
         gender = ?,
         job = ?,
         education_level = ?,
         mobile_phone = ?,
         personal_email = ?,
         national_address = ?,
         photo_url = ?,
         notes = ?,
         short_bio = ?
       WHERE id = ?`,
      [
        String(name || "").trim(),
        resolvedFather.id || null,
        resolvedMother.id || null,
        birth_date || null,
        birth_place || null,
        death_date || null,
        death_place || null,
        Number(is_deceased ? 1 : 0),
        gender || null,
        job || null,
        education_level || null,
        mobile_phone || null,
        personal_email || null,
        national_address || null,
        photo_url || null,
        notes || null,
        short_bio || null,
        req.params.id,
      ]
    );

    await setSpouseNames(req.params.id, spouse_names);
    await logAdminAction(req, "تعديل فرد", "person", req.params.id, { name });
    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تعديل الشخص");
  }
});

app.post("/admin/person/:id/delete", isAuthed, requirePermission("persons"), async (req, res) => {
  try {
    const id = req.params.id;

    const child = await get(
      "SELECT id FROM persons WHERE father_id = ? OR mother_id = ? LIMIT 1",
      [id, id]
    );
    if (child) {
      return res.status(400).send("لا يمكن حذف شخص لديه أبناء. احذف/انقل الأبناء أولاً.");
    }

    await run("DELETE FROM person_spouses WHERE person_id = ?", [id]);
    await run("DELETE FROM persons WHERE id = ?", [id]);
    await logAdminAction(req, "حذف فرد", "person", id, {});

    res.redirect("/admin");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حذف الشخص");
  }
});

/* =========================
   Admin: CMS pages
   ========================= */
app.get("/admin/pages", isAuthed, requirePermission("pages"), async (req, res) => {
  try {
    // ✅ تم إضافة سطر جلب بيانات النبذة (about)
    const about = await get(`SELECT * FROM site_pages WHERE slug='about'`); 
    const support = await get(`SELECT * FROM site_pages WHERE slug='support'`);
    const treepdf = await get(`SELECT * FROM site_pages WHERE slug='tree-pdf'`);
    const timeline = await all(`SELECT * FROM timeline_events ORDER BY "order" ASC`);

    res.render("pages_admin", {
      admin: req.session.admin,
      about, // ✅ تم تمرير المتغير إلى صفحة EJS
      support,
      treepdf,
      timeline,
      saved: req.query.saved === "1",
      deleted: req.query.deleted === "1",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل إدارة الصفحات");
  }
});

app.post("/admin/pages/save", isAuthed, requirePermission("pages"), async (req, res) => {
  try {
    const { slug, title, subtitle, content } = req.body;

    if (slug === "support") {
      const { fund_name, bank_name, account_number, whatsapp, email } = req.body;

      await run(
        `UPDATE site_pages
         SET title = ?,
             subtitle = ?,
             content = ?,
             fund_name = ?,
             bank_name = ?,
             account_number = ?,
             whatsapp = ?,
             email = ?,
             updated_at = datetime('now')
         WHERE slug = ?`,
        [
          title || "",
          subtitle || "",
          content || "",
          fund_name || "",
          bank_name || "",
          account_number || "",
          whatsapp || "",
          email || "",
          slug,
        ]
      );

      return res.redirect("/admin/pages?saved=1");
    }

    await run(
      `UPDATE site_pages
       SET title = ?, subtitle = ?, content = ?, updated_at = datetime('now')
       WHERE slug = ?`,
      [title || "", subtitle || "", content || "", slug]
    );

    res.redirect("/admin/pages?saved=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حفظ الصفحة");
  }
});

/* =========================
   Admin: Tree PDF upload/delete
   ========================= */
app.post("/admin/pages/tree-pdf/upload", isAuthed, requirePermission("pages"), (req, res) => {
  uploadPdf.single("pdf_file")(req, res, async (err) => {
    try {
      if (err) return res.status(400).send(err.message || "Upload error");
      if (!req.file) return res.status(400).send("No PDF uploaded");

      const url = "/uploads/pdfs/" + req.file.filename;

      const old = await get(`SELECT pdf_url FROM site_pages WHERE slug='tree-pdf'`);
      if (
        old?.pdf_url &&
        typeof old.pdf_url === "string" &&
        old.pdf_url.startsWith("/uploads/pdfs/")
      ) {
        const oldPath = path.join(__dirname, "public", old.pdf_url);
        fs.unlink(oldPath, () => {});
      }

      await run(
        `UPDATE site_pages
         SET pdf_url = ?, updated_at = datetime('now')
         WHERE slug = 'tree-pdf'`,
        [url]
      );

      return res.json({ ok: true, url });
    } catch (e) {
      console.error(e);
      return res.status(500).send("Server error");
    }
  });
});

app.post("/admin/pages/tree-pdf/delete", isAuthed, requirePermission("pages"), async (req, res) => {
  try {
    const old = await get(`SELECT pdf_url FROM site_pages WHERE slug='tree-pdf'`);
    if (
      old?.pdf_url &&
      typeof old.pdf_url === "string" &&
      old.pdf_url.startsWith("/uploads/pdfs/")
    ) {
      const oldPath = path.join(__dirname, "public", old.pdf_url);
      fs.unlink(oldPath, () => {});
    }

    await run(
      `UPDATE site_pages
       SET pdf_url = NULL, updated_at = datetime('now')
       WHERE slug = 'tree-pdf'`
    );

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).send("Server error");
  }
});

/* =========================
   Mail Notification Helpers
   ========================= */
function getMailTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    return null;
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || "true") === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

function buildNewsEmailHtml(post, newsUrl) {
  return `
    <div dir="rtl" style="font-family:Arial,Tahoma,sans-serif;line-height:1.8;color:#222">
      <h2 style="color:#1f637a;margin-bottom:10px;">${post.title || "خبر جديد"}</h2>
      <p>${post.summary || post.content || ""}</p>
      <p>
        <a href="${newsUrl}" style="display:inline-block;background:#1f637a;color:#fff;padding:10px 16px;border-radius:10px;text-decoration:none;font-weight:bold">
          قراءة الخبر
        </a>
      </p>
      <hr/>
      <p style="font-size:12px;color:#777">تم إرسال هذه الرسالة لأنك مشترك في أخبار العائلة.</p>
    </div>
  `;
}

async function sendNewsEmailToSubscribers(post, req) {
  const transporter = getMailTransporter();

  if (!transporter) {
    console.warn("SMTP is not configured. Email notification skipped.");
    return { sent: 0, failed: 0, skipped: true };
  }

  const subscribers = await all(`
    SELECT email
    FROM newsletter_subscribers
    WHERE COALESCE(is_active, 1) = 1
      AND TRIM(COALESCE(email, '')) <> ''
  `);

  const newsUrl = `${req.protocol}://${req.get("host")}/news/${post.id}`;
  let sent = 0;
  let failed = 0;

  for (const sub of subscribers) {
    try {
      await transporter.sendMail({
        from: `"${process.env.SMTP_FROM_NAME || "أخبار العائلة"}" <${process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER}>`,
        to: sub.email,
        subject: `خبر جديد: ${post.title}`,
        text: `${post.title}\n\n${post.summary || post.content || ""}\n\n${newsUrl}`,
        html: buildNewsEmailHtml(post, newsUrl),
      });

      sent++;
    } catch (err) {
      failed++;
      console.error("Email send failed:", sub.email, err.message);
    }
  }

  return { sent, failed, skipped: false };
}

/* =========================
   Admin: News CRUD
   ========================= */
app.get("/admin/news", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    const posts = await getAllNewsAdmin();
    res.render("news_admin", {
      admin: req.session.admin,
      posts,
      saved: req.query.saved === "1",
      deleted: req.query.deleted === "1",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل إدارة الأخبار");
  }
});

app.get("/admin/news/new", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    const persons = await all("SELECT id, name, photo_url, job, short_bio FROM persons ORDER BY name ASC");
    res.render("news_form", {
      admin: req.session.admin,
      mode: "new",
      post: null,
      persons,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في فتح نموذج الخبر");
  }
});

app.post("/admin/news/new", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    const {
      title,
      summary,
      content,
      image_url,
      person_id,
      event_date,
      published_at,
      is_active,
      is_pinned,
      notify_enabled,
      publisher_name,
      publisher_phone,
    } = req.body;

    const result = await run(
      `INSERT INTO news_posts (
        title, summary, content, image_url, person_id,
        event_date, published_at, is_active, is_pinned, notify_enabled,
        publisher_name, publisher_phone
      )
      VALUES (?, ?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), datetime('now')), ?, ?, ?, ?, ?)`,
      [
        String(title || "").trim(),
        summary || "",
        content || "",
        image_url || "",
        person_id || null,
        event_date || null,
        published_at || "",
        Number(is_active ? 1 : 0),
        Number(is_pinned ? 1 : 0),
        Number(notify_enabled ? 1 : 0),
        String(publisher_name || "").trim(),
        String(publisher_phone || "").trim(),
      ]
    );

    if (notify_enabled && is_active) {
      await createNewsNotification(result.lastID, title, summary || content);
    }

    await logAdminAction(req, "إضافة خبر", "news", result.lastID, { title });
    res.redirect("/admin/news?saved=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في إضافة الخبر");
  }
});

app.get("/admin/news/:id/edit", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    const post = await get("SELECT * FROM news_posts WHERE id = ?", [req.params.id]);
    if (!post) return res.redirect("/admin/news");

    const persons = await all("SELECT id, name, photo_url, job, short_bio FROM persons ORDER BY name ASC");

    res.render("news_form", {
      admin: req.session.admin,
      mode: "edit",
      post,
      persons,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في فتح تعديل الخبر");
  }
});

app.post("/admin/news/:id/edit", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    const {
      title,
      summary,
      content,
      image_url,
      person_id,
      event_date,
      published_at,
      is_active,
      is_pinned,
      notify_enabled,
      publisher_name,
      publisher_phone,
    } = req.body;

    await run(
      `UPDATE news_posts
       SET title = ?,
           summary = ?,
           content = ?,
           image_url = ?,
           person_id = ?,
           event_date = ?,
           published_at = COALESCE(NULLIF(?, ''), published_at, datetime('now')),
           is_active = ?,
           is_pinned = ?,
           notify_enabled = ?,
           publisher_name = ?,
           publisher_phone = ?
       WHERE id = ?`,
      [
        String(title || "").trim(),
        summary || "",
        content || "",
        image_url || "",
        person_id || null,
        event_date || null,
        published_at || "",
        Number(is_active ? 1 : 0),
        Number(is_pinned ? 1 : 0),
        Number(notify_enabled ? 1 : 0),
        String(publisher_name || "").trim(),
        String(publisher_phone || "").trim(),
        req.params.id,
      ]
    );

    if (notify_enabled && is_active) {
      await createNewsNotification(req.params.id, title, summary || content);
    }

    await logAdminAction(req, "تعديل خبر", "news", req.params.id, { title });
    res.redirect("/admin/news?saved=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تعديل الخبر");
  }
});

app.post("/admin/news/:id/delete", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    await run("DELETE FROM news_posts WHERE id = ?", [req.params.id]);
    await logAdminAction(req, "حذف خبر", "news", req.params.id, {});
    res.redirect("/admin/news?deleted=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حذف الخبر");
  }
});

app.post("/admin/news/:id/pin", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    await run(
      `UPDATE news_posts
       SET is_pinned = CASE WHEN COALESCE(is_pinned, 0) = 1 THEN 0 ELSE 1 END
       WHERE id = ?`,
      [req.params.id]
    );

    res.redirect("/admin/news?saved=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تثبيت الخبر");
  }
});

app.post("/admin/news/:id/notify", isAuthed, requirePermission("news"), async (req, res) => {
  try {
    const post = await get(
      `SELECT *
       FROM news_posts
       WHERE id = ?`,
      [req.params.id]
    );

    if (!post) return res.redirect("/admin/news");

    if (typeof createNewsNotification === "function") {
      await createNewsNotification(post.id, post.title, post.summary || post.content || "");
    }

    await run(`UPDATE news_posts SET notify_enabled = 1 WHERE id = ?`, [post.id]);

    const result = await sendNewsEmailToSubscribers(post, req);

    console.log("News email notification result:", result);

    res.redirect("/admin/news?saved=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في إرسال إشعار الخبر بالبريد");
  }
});

app.get("/admin/news/subscribers", isAuthed, requirePermission("subscribers"), async (req, res) => {
  try {
    const subscribers = await all(`
      SELECT *
      FROM newsletter_subscribers
      ORDER BY id DESC
    `);

    res.render("newsletter_subscribers", {
      admin: req.session.admin,
      subscribers,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل المشتركين");
  }
});

app.post("/admin/news/subscribers/:id/toggle", isAuthed, requirePermission("subscribers"), async (req, res) => {
  try {
    await run(
      `UPDATE newsletter_subscribers
       SET is_active = CASE WHEN COALESCE(is_active, 1) = 1 THEN 0 ELSE 1 END
       WHERE id = ?`,
      [req.params.id]
    );

    res.redirect("/admin/news/subscribers");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تعديل حالة المشترك");
  }
});

app.post("/admin/news/subscribers/:id/delete", isAuthed, requirePermission("subscribers"), async (req, res) => {
  try {
    await run("DELETE FROM newsletter_subscribers WHERE id = ?", [req.params.id]);
    await logAdminAction(req, "حذف مشترك", "subscriber", req.params.id, {});
    res.redirect("/admin/news/subscribers");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حذف المشترك");
  }
});

app.get("/admin/news/subscribers/export.csv", isAuthed, requirePermission("subscribers"), async (req, res) => {
  try {
    const subscribers = await all(`
      SELECT id, email, subscriber_name, created_at, is_active
      FROM newsletter_subscribers
      ORDER BY id DESC
    `);

    const escapeCsv = (v) => {
      const s = String(v ?? "");
      return `"${s.replace(/"/g, '""')}"`;
    };

    const header = ["id", "email", "subscriber_name", "created_at", "is_active"].join(",");
    const lines = subscribers.map((s) =>
      [
        s.id,
        escapeCsv(s.email),
        escapeCsv(s.subscriber_name),
        escapeCsv(s.created_at),
        Number(s.is_active || 0),
      ].join(",")
    );

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="newsletter_subscribers.csv"');
    res.send("\uFEFF" + [header, ...lines].join("\n"));
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تصدير المشتركين");
  }
});

/* =========================
   Admin: News Comments
   ========================= */
app.get("/admin/news/comments", isAuthed, requirePermission("comments"), async (req, res) => {
  try {
    const comments = await all(`
      SELECT
        c.*,
        n.title AS news_title
      FROM news_comments c
      LEFT JOIN news_posts n ON n.id = c.post_id
      ORDER BY c.id DESC
    `);

    res.render("news_comments_admin", {
      admin: req.session.admin,
      comments,
      deleted: req.query.deleted === "1",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل تعليقات الأخبار");
  }
});

app.post("/admin/news/comments/:id/delete", isAuthed, requirePermission("comments"), async (req, res) => {
  try {
    await run(`DELETE FROM news_comments WHERE id = ?`, [req.params.id]);
    await logAdminAction(req, "حذف تعليق", "comment", req.params.id, {});
    res.redirect("/admin/news/comments?deleted=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حذف التعليق");
  }
});

app.get("/admin/news/comments/export.csv", isAuthed, requirePermission("comments"), async (req, res) => {
  try {
    const comments = await all(`
      SELECT
        c.id,
        c.post_id,
        n.title AS news_title,
        c.name,
        c.content,
        c.created_at
      FROM news_comments c
      LEFT JOIN news_posts n ON n.id = c.post_id
      ORDER BY c.id DESC
    `);

    const escapeCsv = (v) => {
      const s = String(v ?? "");
      return `"${s.replace(/"/g, '""')}"`;
    };

    const header = ["id", "post_id", "news_title", "name", "content", "created_at"].join(",");
    const lines = comments.map((c) =>
      [
        c.id,
        c.post_id,
        escapeCsv(c.news_title),
        escapeCsv(c.name),
        escapeCsv(c.content),
        escapeCsv(c.created_at),
      ].join(",")
    );

    const csv = [header, ...lines].join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="news_comments.csv"');
    res.send("\uFEFF" + csv);
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تصدير التعليقات");
  }
});

/* =========================
   Admin: Historical Timeline CRUD
   ========================= */
app.post("/admin/timeline/add", isAuthed, requirePermission("pages"), upload.single("image_file"), async (req, res) => {
  try {
    const { title, description, date, order, visible } = req.body;
    const image_url = req.file ? "/uploads/" + req.file.filename : null;

    await run(
      `INSERT INTO timeline_events (title, description, date, image_url, "order", visible) VALUES (?, ?, ?, ?, ?, ?)`,
      [title || "", description || "", date || "", image_url, order || 0, visible ? 1 : 0]
    );
    res.redirect("/admin/pages?saved=1");
  } catch (err) {
    console.error(err);
    res.status(500).send("Insert error: " + err.message);
  }
});

app.post("/admin/timeline/:id/edit", isAuthed, requirePermission("pages"), upload.single("image_file"), async (req, res) => {
  try {
    const { title, description, date, order, visible } = req.body;
    const image_url = req.file ? "/uploads/" + req.file.filename : null;

    let query = `UPDATE timeline_events SET title=?, description=?, date=?, "order"=?, visible=?`;
    const params = [title || "", description || "", date || "", order || 0, visible ? 1 : 0];

    if (image_url) {
      query += `, image_url=?`;
      params.push(image_url);
    }

    query += ` WHERE id=?`;
    params.push(req.params.id);

    await run(query, params);
    res.redirect("/admin/pages?saved=1");
  } catch (err) {
    console.error(err);
    res.status(500).send("Update error: " + err.message);
  }
});

app.get("/admin/timeline/:id/edit", isAuthed, requirePermission("pages"), (req, res) => {
  const id = req.params.id;
  db.get("SELECT * FROM timeline_events WHERE id = ?", [id], (err, row) => {
    if (err) return res.send("Database error: " + err.message);
    if (!row) return res.send("محطة غير موجودة");
    res.render("edit_timeline", { event: row }); 
  });
});

app.post("/admin/timeline/:id/delete", isAuthed, requirePermission("pages"), async (req, res) => {
  try {
    await run(`DELETE FROM timeline_events WHERE id=?`, [req.params.id]);
    await logAdminAction(req, "حذف محطة زمنية", "timeline", req.params.id, {});
    res.redirect("/admin/pages?deleted=1");
  } catch (err) {
    console.error(err);
    res.status(500).send("Delete error: " + err.message);
  }
});

/* =========================
   Admin: Honor CRUD
   ========================= */
app.get("/admin/honor", isAuthed, requirePermission("honor"), async (req, res) => {
  try {
    const items = await all(`SELECT * FROM honor_items ORDER BY ord ASC, id ASC`);
    res.render("honor_admin", { admin: req.session.admin, items });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل قائمة الشرف");
  }
});

app.get("/admin/honor/new", isAuthed, requirePermission("honor"), async (req, res) => {
  res.render("honor_form", { admin: req.session.admin, mode: "new", item: null });
});

app.post("/admin/honor/new", isAuthed, requirePermission("honor"), async (req, res) => {
  try {
    const { name, field, bio, achievement, photo_url, ord, birth_date, death_date, birth_place } = req.body;
    const person_id = req.body.person_id || await resolvePersonIdByName(name);

    await run(
      `INSERT INTO honor_items (person_id, name, field, bio, achievement, birth_date, death_date, birth_place, photo_url, ord)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        person_id || null,
        name || "",
        field || "",
        bio || "",
        achievement || "",
        birth_date || "",
        death_date || "",
        birth_place || "",
        photo_url || "",
        Number(ord || 1),
      ]
    );

    res.redirect("/admin/honor");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في إضافة عنصر قائمة الشرف");
  }
});

app.get("/admin/honor/:id/edit", isAuthed, requirePermission("honor"), async (req, res) => {
  try {
    const item = await get(`SELECT * FROM honor_items WHERE id=?`, [req.params.id]);
    if (!item) return res.redirect("/admin/honor");

    res.render("honor_form", { admin: req.session.admin, mode: "edit", item });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في فتح تعديل قائمة الشرف");
  }
});

app.post("/admin/honor/:id/edit", isAuthed, requirePermission("honor"), async (req, res) => {
  try {
    const { name, field, bio, achievement, photo_url, ord, birth_date, death_date, birth_place } = req.body;
    const person_id = req.body.person_id || await resolvePersonIdByName(name);

    await run(
      `UPDATE honor_items
       SET person_id=?, name=?, field=?, bio=?, achievement=?, birth_date=?, death_date=?, birth_place=?, photo_url=?, ord=?
       WHERE id=?`,
      [
        person_id || null,
        name || "",
        field || "",
        bio || "",
        achievement || "",
        birth_date || "",
        death_date || "",
        birth_place || "",
        photo_url || "",
        Number(ord || 1),
        req.params.id,
      ]
    );

    res.redirect("/admin/honor");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تعديل عنصر قائمة الشرف");
  }
});

app.post("/admin/honor/:id/delete", isAuthed, requirePermission("honor"), async (req, res) => {
  try {
    await run(`DELETE FROM honor_items WHERE id=?`, [req.params.id]);
    await logAdminAction(req, "حذف سيرة ذاتية", "honor", req.params.id, {});
    res.redirect("/admin/honor");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حذف عنصر قائمة الشرف");
  }
});

/* =========================
   Admin: Roles & Permissions
   ========================= */
app.get("/admin/roles", isAuthed, requireSuperAdmin, async (req, res) => {
  try {
    await ensureAdminRoleSchema();
    const admins = await all(`
      SELECT a.id, a.username, a.person_id, a.display_name, a.role_title, a.permissions,
             a.is_super_admin, a.is_active, a.created_at, p.name AS person_name
      FROM admins a
      LEFT JOIN persons p ON p.id = a.person_id
      ORDER BY a.is_super_admin DESC, a.id ASC
    `);

    const persons = await all(`
      SELECT id, name, job, photo_url
      FROM persons
      ORDER BY name COLLATE NOCASE ASC
    `);

    res.render("roles_admin", {
      admin: req.session.admin,
      admins,
      persons,
      permissionGroups: PERMISSION_GROUPS,
      parsePermissions,
      saved: req.query.saved === "1",
      deleted: req.query.deleted === "1",
      error: req.query.error || "",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل وظائف الأفراد");
  }
});

app.post("/admin/roles/new", isAuthed, requireSuperAdmin, async (req, res) => {
  try {
    await ensureAdminRoleSchema();
    const { person_id, username, password, role_title } = req.body;
    const permissions = normalizeMulti(req.body.permissions).filter(Boolean);
    if (!username || !password) return res.redirect("/admin/roles?error=" + encodeURIComponent("اسم المستخدم وكلمة المرور مطلوبان"));
    if (!permissions.length) return res.redirect("/admin/roles?error=" + encodeURIComponent("اختر صلاحية واحدة على الأقل"));

    const person = person_id ? await get(`SELECT id, name FROM persons WHERE id=?`, [person_id]) : null;
    const passwordHash = await bcrypt.hash(password, 10);

    await run(
      `INSERT INTO admins (username, password_hash, person_id, display_name, role_title, permissions, is_super_admin, is_active)
       VALUES (?, ?, ?, ?, ?, ?, 0, 1)`,
      [
        username.trim(),
        passwordHash,
        person ? person.id : null,
        person ? person.name : (req.body.display_name || username).trim(),
        role_title || "محرر",
        JSON.stringify(permissions),
      ]
    );

    res.redirect("/admin/roles?saved=1");
  } catch (e) {
    console.error(e);
    const msg = e && String(e.message || e).includes("UNIQUE") ? "اسم المستخدم موجود بالفعل" : "حدث خطأ أثناء إضافة المستخدم";
    res.redirect("/admin/roles?error=" + encodeURIComponent(msg));
  }
});

app.post("/admin/roles/:id/update", isAuthed, requireSuperAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const current = await get(`SELECT * FROM admins WHERE id=?`, [id]);
    if (!current) return res.redirect("/admin/roles");
    if (Number(current.is_super_admin) === 1 && Number(id) === Number(req.session.admin.id)) {
      return res.redirect("/admin/roles?error=" + encodeURIComponent("لا يمكن تعديل صلاحيات المدير الرئيسي الحالي من هنا"));
    }

    const { person_id, username, password, role_title, is_active } = req.body;
    const permissions = normalizeMulti(req.body.permissions).filter(Boolean);
    const person = person_id ? await get(`SELECT id, name FROM persons WHERE id=?`, [person_id]) : null;

    const params = [
      username.trim(),
      person ? person.id : null,
      person ? person.name : (req.body.display_name || username).trim(),
      role_title || current.role_title || "محرر",
      JSON.stringify(permissions.length ? permissions : parsePermissions(current.permissions)),
      is_active ? 1 : 0,
    ];

    let sql = `UPDATE admins SET username=?, person_id=?, display_name=?, role_title=?, permissions=?, is_active=?`;
    if (password && password.trim()) {
      sql += `, password_hash=?`;
      params.push(await bcrypt.hash(password, 10));
    }
    sql += ` WHERE id=?`;
    params.push(id);

    await run(sql, params);
    res.redirect("/admin/roles?saved=1");
  } catch (e) {
    console.error(e);
    const msg = e && String(e.message || e).includes("UNIQUE") ? "اسم المستخدم موجود بالفعل" : "حدث خطأ أثناء تحديث المستخدم";
    res.redirect("/admin/roles?error=" + encodeURIComponent(msg));
  }
});

app.post("/admin/roles/:id/delete", isAuthed, requireSuperAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const current = await get(`SELECT * FROM admins WHERE id=?`, [id]);
    if (!current) return res.redirect("/admin/roles");
    if (Number(current.is_super_admin) === 1 || id === Number(req.session.admin.id)) {
      return res.redirect("/admin/roles?error=" + encodeURIComponent("لا يمكن حذف المدير الرئيسي أو حسابك الحالي"));
    }
    await run(`DELETE FROM admins WHERE id=?`, [id]);
    await logAdminAction(req, "حذف مستخدم إداري", "admin", id, { username: current.username });
    res.redirect("/admin/roles?deleted=1");
  } catch (e) {
    console.error(e);
    res.redirect("/admin/roles?error=" + encodeURIComponent("حدث خطأ أثناء الحذف"));
  }
});



app.get("/admin/person-requests", isAuthed, requirePermission("person_requests"), async (req, res) => {
  try {
    const status = ["pending", "approved", "rejected"].includes(req.query.status) ? req.query.status : "pending";
    const referenceSearch = cleanText(req.query.reference || "", 80).toUpperCase();

    let requests;
    if (referenceSearch) {
      requests = await all(
        `SELECT pr.*, a.username AS reviewed_by_username, p.name AS created_person_name
         FROM person_requests pr
         LEFT JOIN admins a ON pr.reviewed_by = a.id
         LEFT JOIN persons p ON pr.created_person_id = p.id
         WHERE UPPER(pr.reference_code) = ?
         ORDER BY pr.id DESC`,
        [referenceSearch]
      );
    } else {
      requests = await all(
        `SELECT pr.*, a.username AS reviewed_by_username, p.name AS created_person_name
         FROM person_requests pr
         LEFT JOIN admins a ON pr.reviewed_by = a.id
         LEFT JOIN persons p ON pr.created_person_id = p.id
         WHERE pr.status = ?
         ORDER BY pr.id DESC`,
        [status]
      );
    }

    const counts = await getRequestCounts();
    res.render("person_requests_admin", {
      admin: req.session.admin,
      requests,
      counts,
      status,
      searchReference: referenceSearch,
      isReferenceSearch: Boolean(referenceSearch),
      saved: req.query.saved === "1",
      rejected: req.query.rejected === "1",
      deleted: req.query.deleted === "1",
      error: req.query.error || "",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل طلبات الأفراد");
  }
});

app.get("/admin/person-requests/:id", isAuthed, requirePermission("person_requests"), async (req, res) => {
  try {
    const request = await get(`SELECT * FROM person_requests WHERE id = ?`, [req.params.id]);
    if (!request) return res.redirect("/admin/person-requests");
    const fatherLineageName = request.father_lineage_name || await lineageLabelForPersonId(request.father_id);
    const motherLineageName = request.mother_lineage_name || await lineageLabelForPersonId(request.mother_id);
    res.render("person_request_review", {
      admin: req.session.admin,
      request,
      persons: [],
      fatherLineageName,
      motherLineageName,
      spouseText: listToTextarea(request.spouse_names),
      childrenText: listToTextarea(request.children_names),
      error: req.query.error || "",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في فتح طلب الفرد");
  }
});

app.post("/admin/person-requests/:id/delete", isAuthed, requirePermission("person_requests"), async (req, res) => {
  try {
    const request = await get(`SELECT * FROM person_requests WHERE id = ?`, [req.params.id]);
    if (!request) return res.redirect("/admin/person-requests?error=" + encodeURIComponent("الطلب غير موجود"));

    await run(`DELETE FROM person_requests WHERE id = ?`, [req.params.id]);
    await logAdminAction(req, "حذف طلب إضافة فرد", "person_request", req.params.id, {
      reference_code: request.reference_code,
      name: request.name,
      status: request.status,
      created_person_id: request.created_person_id || null,
    });

    const backStatus = ["pending", "approved", "rejected"].includes(request.status) ? request.status : "pending";
    res.redirect(`/admin/person-requests?status=${encodeURIComponent(backStatus)}&deleted=1`);
  } catch (e) {
    console.error(e);
    res.redirect("/admin/person-requests?error=" + encodeURIComponent("حدث خطأ أثناء حذف الطلب"));
  }
});

app.post("/admin/person-requests/:id/approve", isAuthed, requirePermission("person_requests"), async (req, res) => {
  try {
    const request = await get(`SELECT * FROM person_requests WHERE id = ?`, [req.params.id]);
    if (!request) return res.redirect("/admin/person-requests");
    if (request.status !== "pending") {
      return res.redirect("/admin/person-requests/" + req.params.id + "?error=" + encodeURIComponent("تمت مراجعة هذا الطلب مسبقًا"));
    }

    const body = req.body || {};
    const name = cleanText(body.name || request.name, 180);
    if (!name) {
      return res.redirect("/admin/person-requests/" + req.params.id + "?error=" + encodeURIComponent("اسم الفرد مطلوب قبل الاعتماد"));
    }

    const gender = cleanText(body.gender || request.gender, 20) || null;
    const spouseList = linesToCleanArray(body.spouse_names ?? request.spouse_names, 20, 160);
    const childrenList = linesToCleanArray(body.children_names ?? request.children_names, 40, 160);
    const fatherLineageName = cleanText(body.father_lineage_name || request.father_lineage_name, 220);
    const motherLineageName = cleanText(body.mother_lineage_name || request.mother_lineage_name, 220);
    const resolvedFather = await resolveOptionalLineageId(fatherLineageName);
    const resolvedMother = await resolveOptionalLineageId(motherLineageName);
    if (fatherLineageName && !resolvedFather.id) {
      return res.redirect("/admin/person-requests/" + req.params.id + "?error=" + encodeURIComponent(resolvedFather.result?.message || "لم يتم العثور على الأب بهذا التسلسل الثلاثي"));
    }

    const result = await run(
      `INSERT INTO persons (
        name, father_id, mother_id, birth_date, birth_place,
        death_date, death_place, is_deceased, gender,
        job, education_level, mobile_phone, personal_email, national_address, lineage, photo_url, notes, short_bio
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        resolvedFather.id || null,
        resolvedMother.id || null,
        cleanText(body.birth_date, 40) || null,
        cleanText(body.birth_place, 180) || null,
        cleanText(body.death_date, 40) || null,
        cleanText(body.death_place, 180) || null,
        Number(body.is_deceased ? 1 : 0),
        gender,
        cleanText(body.job, 220) || null,
        cleanText(body.education_level, 120) || null,
        cleanText(body.mobile_phone, 80) || null,
        cleanText(body.personal_email, 180) || null,
        cleanText(body.national_address, 300) || null,
        null,
        body.photo_url || request.photo_url || null,
        cleanText(body.notes, 3000) || null,
        cleanText(body.short_bio, 2000) || null,
      ]
    );

    const personId = result.lastID;
    await setSpouseNames(personId, spouseList);

    for (const childName of childrenList) {
      const childGender = null;
      const fatherId = gender === "male" || gender === "ذكر" ? personId : null;
      const motherId = gender === "female" || gender === "أنثى" || gender === "انثى" ? personId : null;
      await run(
        `INSERT INTO persons (name, father_id, mother_id, gender, notes)
         VALUES (?, ?, ?, ?, ?)`,
        [childName, fatherId, motherId, childGender, "تمت إضافته تلقائيًا من طلب إضافة فرد"]
      );
    }

    await run(
      `UPDATE person_requests
       SET status='approved', created_person_id=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP, admin_note=?, father_lineage_name=?, mother_lineage_name=?
       WHERE id=?`,
      [personId, req.session.admin.id, cleanText(body.admin_note, 1000) || null, fatherLineageName || null, motherLineageName || null, req.params.id]
    );

    await logAdminAction(req, "اعتماد طلب إضافة فرد", "person_request", req.params.id, { personId, name });
    res.redirect("/admin/person-requests?saved=1");
  } catch (e) {
    console.error(e);
    res.redirect("/admin/person-requests/" + req.params.id + "?error=" + encodeURIComponent("حدث خطأ أثناء اعتماد الطلب"));
  }
});

app.post("/admin/person-requests/:id/reject", isAuthed, requirePermission("person_requests"), async (req, res) => {
  try {
    const request = await get(`SELECT * FROM person_requests WHERE id = ?`, [req.params.id]);
    if (!request) return res.redirect("/admin/person-requests");
    if (request.status !== "pending") {
      return res.redirect("/admin/person-requests/" + req.params.id + "?error=" + encodeURIComponent("تمت مراجعة هذا الطلب مسبقًا"));
    }
    await run(
      `UPDATE person_requests
       SET status='rejected', reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP, admin_note=?
       WHERE id=?`,
      [req.session.admin.id, cleanText(req.body.admin_note, 1000) || "تم رفض الطلب", req.params.id]
    );
    await logAdminAction(req, "رفض طلب إضافة فرد", "person_request", req.params.id, { reason: req.body.admin_note });
    res.redirect("/admin/person-requests?status=rejected&rejected=1");
  } catch (e) {
    console.error(e);
    res.redirect("/admin/person-requests/" + req.params.id + "?error=" + encodeURIComponent("حدث خطأ أثناء رفض الطلب"));
  }
});

app.get("/admin/no-access", isAuthed, (req, res) => {
  res.status(403).render("admin_no_access", {
    admin: req.session.admin,
    permissionGroups: PERMISSION_GROUPS,
    userCan: (perm) => userCan(req.session.admin, perm),
  });
});

/* =========================
   Admin: Support Messages
   ========================= */
app.get("/admin/support-messages", isAuthed, requirePermission("support"), async (req, res) => {
  try {
    const msgs = await all(`
      SELECT *
      FROM support_messages
      ORDER BY id DESC
    `);

    res.render("support_messages", {
      admin: req.session.admin,
      msgs,
      deleted: req.query.deleted === "1",
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل الرسائل");
  }
});

app.post("/admin/support-messages/:id/delete", isAuthed, requirePermission("support"), async (req, res) => {
  try {
    await run(`DELETE FROM support_messages WHERE id=?`, [req.params.id]);
    await logAdminAction(req, "حذف رسالة دعم", "support_message", req.params.id, {});
    res.redirect("/admin/support-messages?deleted=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في حذف الرسالة");
  }
});

app.get("/admin/support-messages/export.csv", isAuthed, requirePermission("support"), async (req, res) => {
  try {
    const msgs = await all(`
      SELECT id, sender_name, phone, message, created_at
      FROM support_messages
      ORDER BY id DESC
    `);

    const escapeCsv = (v) => {
      const s = String(v ?? "");
      return `"${s.replace(/"/g, '""')}"`;
    };

    const header = ["id", "sender_name", "phone", "message", "created_at"].join(",");
    const lines = msgs.map((m) =>
      [
        m.id,
        escapeCsv(m.sender_name),
        escapeCsv(m.phone),
        escapeCsv(m.message),
        escapeCsv(m.created_at),
      ].join(",")
    );

    const csv = [header, ...lines].join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="support_messages.csv"');
    res.send("\uFEFF" + csv);
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تصدير CSV");
  }
});

/* =========================
   404
   ========================= */
app.use((req, res) => {
  res.status(404).send("الصفحة غير موجودة");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Running on", PORT));