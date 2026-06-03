require("dotenv").config();
const nodemailer = require("nodemailer");

const express = require("express");
const path = require("path");
const fs = require("fs");
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
    const isAllowedAsset = req.path === "/theme.js" || req.path.startsWith("/assets/") || req.path.startsWith("/uploads/");
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
   Public Routes
   ========================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
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
        death_date, death_place, is_deceased, gender, job, lineage,
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
        death_date, death_place, is_deceased, gender, job, lineage,
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
    const persons = await all("SELECT id, name FROM persons ORDER BY name ASC");
    res.render("person_form", {
      mode: "new",
      persons,
      person: null,
      spouseNames: [],
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
      birth_date,
      birth_place,
      death_date,
      death_place,
      is_deceased,
      gender,
      job,
      mobile_phone,
      personal_email,
      national_address,
      photo_url,
      notes,
      short_bio,
    } = req.body;

    const spouse_names = req.body.spouse_names;

    const result = await run(
      `INSERT INTO persons (
        name, father_id, mother_id, birth_date, birth_place,
        death_date, death_place, is_deceased, gender,
        job, mobile_phone, personal_email, national_address, lineage, photo_url, notes, short_bio
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        String(name || "").trim(),
        father_id || null,
        mother_id || null,
        birth_date || null,
        birth_place || null,
        death_date || null,
        death_place || null,
        Number(is_deceased ? 1 : 0),
        gender || null,
        job || null,
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

    const persons = await all("SELECT id, name FROM persons WHERE id != ? ORDER BY name ASC", [req.params.id]);
    const spouseRows = await getSpouseNames(person.id);
    const spouseNames = spouseRows.map((x) => x.spouse_name);

    res.render("person_form", {
      mode: "edit",
      persons,
      person,
      spouseNames,
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
      birth_date,
      birth_place,
      death_date,
      death_place,
      is_deceased,
      gender,
      job,
      mobile_phone,
      personal_email,
      national_address,
      photo_url,
      notes,
      short_bio,
    } = req.body;

    const spouse_names = req.body.spouse_names;

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
         mobile_phone = ?,
         personal_email = ?,
         national_address = ?,
         photo_url = ?,
         notes = ?,
         short_bio = ?
       WHERE id = ?`,
      [
        String(name || "").trim(),
        father_id || null,
        mother_id || null,
        birth_date || null,
        birth_place || null,
        death_date || null,
        death_place || null,
        Number(is_deceased ? 1 : 0),
        gender || null,
        job || null,
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