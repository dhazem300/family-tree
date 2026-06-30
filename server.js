require("dotenv").config();
const nodemailer = require("nodemailer");

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const db = require("./db");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const multer = require("multer");
const rateLimit = require("express-rate-limit");

// Optional OAuth support. The site still works with email/password if these
// packages or provider credentials are not installed/configured yet.
let passport = null;
let GoogleStrategy = null;
let SocketIOServer = null;
try {
  SocketIOServer = require("socket.io").Server;
} catch (e) {
  SocketIOServer = null;
}
try {
  passport = require("passport");
  GoogleStrategy = require("passport-google-oauth20").Strategy;
} catch (e) {
  passport = null;
  GoogleStrategy = null;
}
const { answerFromAssistantKnowledge } = require("./assistantKnowledge");
const { answerFromEntertainment } = require("./assistantEntertainment");

const app = express();
const server = http.createServer(app);
let io = null;

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=(self)");
  next();
});

app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));

const sessionSecret = process.env.SESSION_SECRET || "CHANGE_THIS_SECRET";
if (sessionSecret === "CHANGE_THIS_SECRET") {
  console.warn("Security warning: set SESSION_SECRET in .env before production.");
}

app.use(
  session({
    name: process.env.SESSION_COOKIE_NAME || "family_tree_sid",
    store: new SQLiteStore({ db: "sessions.db", dir: __dirname }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: envFlag("COOKIE_SECURE", process.env.NODE_ENV === "production"),
      maxAge: Number(process.env.SESSION_MAX_AGE_MS || 1000 * 60 * 60 * 24 * 7),
    },
  })
);

if (passport) {
  app.use(passport.initialize());
  app.use(passport.session());
}

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

// Private-site gate: every public page, API, image and static file is blocked
// unless the visitor has a normal site account session. Admin routes keep their
// own independent login flow.
app.use(async (req, res, next) => {
  try {
    if (isPublicAccessPath(req.path)) return next();

    const userSession = req.session?.siteUser || null;
    if (!userSession?.id) {
      if (req.path.startsWith("/api/")) {
        return res.status(401).json({ ok: false, loginRequired: true, redirect: "/login" });
      }
      const nextUrl = encodeURIComponent(req.originalUrl || "/");
      return res.redirect(`/login?next=${nextUrl}`);
    }

    const now = Date.now();
    const lastCheck = Number(req.session.siteUserCheckedAt || 0);
    if (!lastCheck || now - lastCheck > 60 * 1000) {
      const fresh = await getSiteUserById(userSession.id);
      if (!fresh || Number(fresh.is_active) === 0) {
        delete req.session.siteUser;
        delete req.session.siteUserCheckedAt;
        return res.redirect("/login?error=" + encodeURIComponent("تم إيقاف الحساب أو لم يعد متاحًا"));
      }
      const approvalStatus = String(fresh.approval_status || "approved");
      req.session.siteUser = publicSiteUserSession(fresh);
      if (approvalStatus !== "approved") {
        res.locals.siteUser = req.session.siteUser;
        if (req.path === "/account-pending" || req.path === "/logout" || req.path === "/theme.js") return next();
        if (req.path.startsWith("/api/")) return res.status(403).json({ ok:false, pendingApproval:true, status: approvalStatus, redirect:"/account-pending" });
        return res.redirect("/account-pending");
      }
      req.session.siteUser = publicSiteUserSession(fresh);
      req.session.siteUserCheckedAt = now;
      await run(`UPDATE site_users SET last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [fresh.id]).catch(() => {});
    }

    res.locals.siteUser = req.session.siteUser;
    maybeLogSiteVisit(req);
    return next();
  } catch (e) {
    console.error("private site gate error:", e);
    return next(e);
  }
});

app.use(express.static(path.join(__dirname, "public"), {
  index: false,
  etag: true,
  maxAge: "7d",
  setHeaders: (res, filePath) => {
    if (/\.(html|ejs)$/i.test(filePath) || /theme\.js$/i.test(filePath)) {
      res.setHeader("Cache-Control", "no-cache");
    } else if (/\.(png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|pdf)$/i.test(filePath)) {
      res.setHeader("Cache-Control", "public, max-age=604800");
    }
  }
}));


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
  { key: "users", label: "مستخدمي الموقع", description: "مراجعة حسابات المستخدمين ونشاطهم داخل الموقع" },
  { key: "chats", label: "محادثات الموقع", description: "إدارة الشات العام والرسائل بين المستخدمين" },
  { key: "approvals", label: "مركز الموافقات", description: "مراجعة الحسابات الجديدة وطلبات الربط والمحتوى المرسل" },
  { key: "reports", label: "البلاغات العامة", description: "مراجعة بلاغات الحسابات والمحتوى" },
  { key: "events", label: "مناسبات العائلة", description: "اعتماد وإدارة مناسبات العائلة" },
  { key: "gallery", label: "معرض الصور", description: "اعتماد وإدارة صور ووثائق العائلة" },
  { key: "backups", label: "النسخ الاحتياطي", description: "تنزيل نسخة احتياطية من قاعدة البيانات والملفات" },
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
    users: "/admin/users",
    chats: "/admin/chats",
    approvals: "/admin/approvals",
    reports: "/admin/approvals#reports",
    events: "/admin/events",
    gallery: "/admin/gallery",
    backups: "/admin/backups",
  };
  if (!admin) return "/admin/login";
  if (Number(admin.is_super_admin) === 1) return "/admin";
  const permissions = parsePermissions(admin.permissions);
  const first = permissions.find((p) => map[p]);
  return first ? map[first] : "/admin/no-access";
}

async function isAuthed(req, res, next) {
  if (req.session?.admin) {
    try {
      res.locals.admin = req.session.admin;
      res.locals.userCan = (permission) => userCan(req.session.admin, permission);
      res.locals.permissionGroups = PERMISSION_GROUPS;
      res.locals.adminPendingCounts = await getAdminPendingCounts().catch(() => ({}));
      return next();
    } catch (e) {
      return next(e);
    }
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


function requireAnyPermission(permissions = []) {
  return function (req, res, next) {
    if (permissions.some((permission) => userCan(req.session?.admin, permission))) return next();
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

function isInsideDir(parentDir, childPath) {
  const relative = path.relative(parentDir, childPath);
  return Boolean(relative) && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function uploadedUrlToDiskPath(fileUrl) {
  const value = String(fileUrl || "").trim();
  if (!value || !value.startsWith("/uploads/")) return null;
  if (/^https?:\/\//i.test(value)) return null;
  const cleanUrl = value.split("?")[0].split("#")[0];
  const decoded = decodeURIComponent(cleanUrl).replace(/\\/g, "/");
  const relative = decoded.replace(/^\/uploads\/+/, "");
  if (!relative || relative.includes("..")) return null;
  const absolute = path.resolve(uploadsDir, relative);
  if (!isInsideDir(uploadsDir, absolute)) return null;
  return absolute;
}

async function removeUploadedFileByUrl(fileUrl) {
  try {
    const absolute = uploadedUrlToDiskPath(fileUrl);
    if (!absolute) return;
    await fs.promises.unlink(absolute).catch((err) => {
      if (err?.code !== "ENOENT") throw err;
    });

    // امسح الصورة المصغّرة إن وُجدت، بدون التأثير على أي ملف آخر.
    const requested = path.basename(absolute);
    const safeName = requested.replace(/[^a-zA-Z0-9._-]/g, "_").replace(/\.[^.]+$/, "") || "thumb";
    const thumbPath = path.join(thumbsDir, safeName + ".webp");
    await fs.promises.unlink(thumbPath).catch((err) => {
      if (err?.code !== "ENOENT") throw err;
    });
  } catch (e) {
    console.error("remove uploaded image error:", e.message || e);
  }
}

function removeUploadedFilesFromRequest(files = {}) {
  const list = Object.values(files || {}).flat().filter(Boolean);
  return Promise.all(list.map((file) => fs.promises.unlink(file.path).catch(() => {})));
}

const pdfUploadsDir = path.join(__dirname, "public", "uploads", "pdfs");
fs.mkdirSync(pdfUploadsDir, { recursive: true });

/* =========================
   Multer uploads
   ========================= */
// حدود رفع الصور.
// ملاحظة: صور الحساب الشخصي لها حدود مستقلة أوضح من باقي صور الموقع.
const MB = 1024 * 1024;
const MAX_PROFILE_AVATAR_UPLOAD_SIZE = Number(process.env.MAX_PROFILE_AVATAR_UPLOAD_SIZE || 10 * MB); // الصورة الشخصية: 10MB افتراضيًا
const MAX_PROFILE_COVER_UPLOAD_SIZE = Number(process.env.MAX_PROFILE_COVER_UPLOAD_SIZE || 20 * MB);   // صورة الغلاف: 20MB افتراضيًا
const MAX_IMAGE_UPLOAD_SIZE = Number(process.env.MAX_IMAGE_UPLOAD_SIZE || 20 * MB);
const MAX_CHAT_UPLOAD_SIZE = Number(process.env.MAX_CHAT_UPLOAD_SIZE || 15 * MB);
const MAX_PDF_UPLOAD_SIZE = Number(process.env.MAX_PDF_UPLOAD_SIZE || 25 * MB);

const ALLOWED_IMAGE_MIMES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
const ALLOWED_IMAGE_EXTS = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif"]);
const ALLOWED_AUDIO_MIMES = new Set(["audio/webm", "audio/ogg", "audio/mpeg", "audio/mp3", "audio/mp4", "audio/wav", "audio/x-wav", "audio/aac"]);
const ALLOWED_AUDIO_EXTS = new Set([".webm", ".ogg", ".mp3", ".m4a", ".mp4", ".wav", ".aac"]);

function safeUploadBaseName(value, fallback = "file") {
  return String(value || fallback)
    .normalize("NFKD")
    .replace(/[\/]+/g, "-")
    .replace(/\s+/g, "_")
    .replace(/[^a-zA-Z0-9._\-؀-ۿ]/g, "")
    .replace(/^\.+/, "")
    .slice(0, 70) || fallback;
}

function safeUploadFilename(originalName, fallbackExt = ".bin") {
  const rawExt = path.extname(String(originalName || "")).toLowerCase();
  const ext = rawExt && rawExt.length <= 10 ? rawExt : fallbackExt;
  const base = safeUploadBaseName(path.basename(String(originalName || "file"), rawExt), "file");
  return `${Date.now()}-${crypto.randomBytes(8).toString("hex")}-${base}${ext}`;
}

function isAllowedImageFile(file) {
  const mime = String(file.mimetype || "").toLowerCase();
  const ext = path.extname(String(file.originalname || "")).toLowerCase();
  return ALLOWED_IMAGE_MIMES.has(mime) && ALLOWED_IMAGE_EXTS.has(ext);
}

function imageFileFilter(req, file, cb) {
  if (isAllowedImageFile(file)) return cb(null, true);
  return cb(new Error("يسمح برفع الصور فقط بصيغ JPG / PNG / WEBP / GIF وبحجم مناسب."));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, safeUploadFilename(file.originalname, ".jpg")),
});
const upload = multer({
  storage,
  fileFilter: imageFileFilter,
  limits: { fileSize: MAX_IMAGE_UPLOAD_SIZE, files: 6 },
});

const profileImageUpload = multer({
  storage,
  fileFilter: imageFileFilter,
  limits: {
    fileSize: Math.max(MAX_PROFILE_AVATAR_UPLOAD_SIZE, MAX_PROFILE_COVER_UPLOAD_SIZE),
    files: 3,
  },
});
const profileImageUploadFields = profileImageUpload.fields([
  { name: "avatar_file", maxCount: 1 },
  { name: "avatar_file_alt", maxCount: 1 },
  { name: "cover_file", maxCount: 1 },
]);

function formatBytesArabic(bytes) {
  const mb = Number(bytes || 0) / MB;
  return `${Number.isInteger(mb) ? mb : mb.toFixed(1)} ميجابايت`;
}

function profileImageLimitMessage(field = "") {
  const isCover = field === "cover_file";
  const limit = isCover ? MAX_PROFILE_COVER_UPLOAD_SIZE : MAX_PROFILE_AVATAR_UPLOAD_SIZE;
  return isCover
    ? `حجم صورة الغلاف كبير. الحد الأقصى لصورة الغلاف هو ${formatBytesArabic(limit)}.`
    : `حجم الصورة الشخصية كبير. الحد الأقصى للصورة الشخصية هو ${formatBytesArabic(limit)}.`;
}

function profileImageUploadHandler(fallbackPath = "/account") {
  return function (req, res, next) {
    profileImageUploadFields(req, res, function (err) {
      if (!err) return next();
      const message = err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE"
        ? profileImageLimitMessage(err.field)
        : (err.message || "تعذر رفع الصورة. تأكد من النوع والحجم.");
      const url = `${fallbackPath}?error=${encodeURIComponent(message)}`;
      return res.redirect(url);
    });
  };
}

function validateProfileImageSizes(files = {}) {
  const avatarFiles = [files?.avatar_file?.[0], files?.avatar_file_alt?.[0]].filter(Boolean);
  const coverFile = files?.cover_file?.[0] || null;
  for (const file of avatarFiles) {
    if (Number(file.size || 0) > MAX_PROFILE_AVATAR_UPLOAD_SIZE) return profileImageLimitMessage("avatar_file");
  }
  if (coverFile && Number(coverFile.size || 0) > MAX_PROFILE_COVER_UPLOAD_SIZE) return profileImageLimitMessage("cover_file");
  return "";
}

const chatUploadsDir = path.join(__dirname, "public", "uploads", "chat");
fs.mkdirSync(chatUploadsDir, { recursive: true });
const chatStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, chatUploadsDir),
  filename: (req, file, cb) => {
    const mime = String(file.mimetype || "").toLowerCase();
    const fallbackExt = mime.startsWith("audio/") ? ".webm" : ".jpg";
    cb(null, safeUploadFilename(file.originalname || "chat-file", fallbackExt));
  },
});
function chatFileFilter(req, file, cb) {
  const mime = String(file.mimetype || "").toLowerCase();
  const ext = path.extname(String(file.originalname || "")).toLowerCase();
  const okImage = ALLOWED_IMAGE_MIMES.has(mime) && ALLOWED_IMAGE_EXTS.has(ext);
  const okAudio = ALLOWED_AUDIO_MIMES.has(mime) && ALLOWED_AUDIO_EXTS.has(ext);
  const okBrowserBlob = mime === "application/octet-stream" && ALLOWED_AUDIO_EXTS.has(ext);
  if (okImage || okAudio || okBrowserBlob) return cb(null, true);
  return cb(new Error("يسمح بإرفاق الصور والتسجيلات الصوتية فقط داخل الشات."));
}
const chatUpload = multer({
  storage: chatStorage,
  fileFilter: chatFileFilter,
  limits: { fileSize: MAX_CHAT_UPLOAD_SIZE, files: 1 },
});

const pdfStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, pdfUploadsDir),
  filename: (req, file, cb) => cb(null, safeUploadFilename(file.originalname || "file.pdf", ".pdf")),
});
function pdfFileFilter(req, file, cb) {
  const okByMime = String(file.mimetype || "").toLowerCase() === "application/pdf";
  const okByName = /\.pdf$/i.test(file.originalname || "");
  if (okByMime && okByName) return cb(null, true);
  cb(new Error("Only PDF files are allowed"));
}
const uploadPdf = multer({
  storage: pdfStorage,
  fileFilter: pdfFileFilter,
  limits: { fileSize: MAX_PDF_UPLOAD_SIZE, files: 1 },
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

function isPublicAccessPath(pathname) {
  const p = String(pathname || "");
  if (p === "/login" || p === "/register" || p === "/logout" || p === "/account-pending") return true;
  if (p.startsWith("/auth/")) return true;
  if (p.startsWith("/admin")) return true;
  if (p === "/theme.js" || p === "/favicon.ico" || p === "/robots.txt") return true;
  if (p.startsWith("/assets/")) return true;
  if (p.startsWith("/uploads/")) return true;
  if (p.startsWith("/image-thumb/")) return true;
  if (p.startsWith("/images/")) return true;
  return false;
}

function isStaticLikePath(pathname) {
  return /\.(css|js|png|jpg|jpeg|gif|svg|webp|ico|map|woff2?|ttf|pdf)$/i.test(String(pathname || ""));
}

function safeRedirectUrl(value, fallback = "/") {
  const v = String(value || "").trim();
  if (!v || !v.startsWith("/") || v.startsWith("//")) return fallback;
  if (v.startsWith("/login") || v.startsWith("/register") || v.startsWith("/auth/")) return fallback;
  return v;
}

function publicSiteUserSession(user) {
  return {
    id: user.id,
    full_name: user.full_name || "",
    father_name: user.father_name || "",
    email: user.email || "",
    phone: user.phone || "",
    country: user.country || "",
    city: user.city || "",
    provider: user.provider || "email",
    avatar_url: user.avatar_url || "",
    cover_url: user.cover_url || "",
    avatar_pos_x: user.avatar_pos_x ?? 50,
    avatar_pos_y: user.avatar_pos_y ?? 50,
    cover_pos_x: user.cover_pos_x ?? 50,
    cover_pos_y: user.cover_pos_y ?? 50,
    chat_privacy: user.chat_privacy || "all",
    approval_status: user.approval_status || "approved",
    verification_status: user.verification_status || "unverified",
    matched_person_id: user.matched_person_id || null,
  };
}

function normalizePhone(value) {
  return cleanText(value, 80).replace(/[^0-9+\-\s]/g, "").trim();
}

function optionalUrl(value, max = 300) {
  const v = cleanText(value, max);
  if (!v) return "";
  if (/^(https?:\/\/)/i.test(v)) return v;
  if (/^(www\.)/i.test(v)) return "https://" + v;
  return v;
}

function normalizePercent(value, fallback = 50) {
  const n = Number.parseFloat(String(value ?? "").replace(",", "."));
  const base = Number.isFinite(n) ? n : Number.parseFloat(fallback);
  const safe = Number.isFinite(base) ? base : 50;
  return Math.max(0, Math.min(100, safe)).toFixed(2);
}

function getSiteUserAvatar(user) {
  return user?.avatar_url || "/assets/default-avatar.svg";
}

function extractSiteUserProfileFields(body = {}) {
  const childrenRaw = String(body.children_count ?? "").trim();
  let childrenCount = childrenRaw === "" ? null : Number.parseInt(childrenRaw, 10);
  if (!Number.isFinite(childrenCount) || childrenCount < 0) childrenCount = null;
  if (childrenCount !== null && childrenCount > 99) childrenCount = 99;

  return {
    full_name: cleanText(body.full_name, 180),
    father_name: cleanText(body.father_name, 180),
    mother_name: cleanText(body.mother_name, 180),
    children_count: childrenCount,
    birth_date: cleanText(body.birth_date, 40),
    origin_place: cleanText(body.origin_place, 180),
    current_residence: cleanText(body.current_residence, 180),
    phone: normalizePhone(body.phone),
    phone_alt: normalizePhone(body.phone_alt),
    email: String(body.email || "").trim().toLowerCase(),
    work: cleanText(body.work, 180),
    qualification: cleanText(body.qualification, 180),
    spouse_family: cleanText(body.spouse_family, 180),
    spouse_name: cleanText(body.spouse_name, 180),
    country: cleanText(body.country, 120),
    city: cleanText(body.city, 120),
    facebook_url: optionalUrl(body.facebook_url),
    instagram_url: optionalUrl(body.instagram_url),
    x_url: optionalUrl(body.x_url),
    linkedin_url: optionalUrl(body.linkedin_url),
    chat_privacy: ["all", "linked_only", "nobody"].includes(String(body.chat_privacy || "all")) ? String(body.chat_privacy || "all") : "all",
    profile_visibility: ["members", "linked_only", "private"].includes(String(body.profile_visibility || "members")) ? String(body.profile_visibility || "members") : "members",
    show_phone: body.show_phone === "1" || body.show_phone === "on" ? 1 : 0,
    show_email: body.show_email === "1" || body.show_email === "on" ? 1 : 0,
    show_birth_date: body.show_birth_date === "1" || body.show_birth_date === "on" ? 1 : 0,
    show_social_links: body.show_social_links === "1" || body.show_social_links === "on" ? 1 : 0,
  };
}

function isSiteUserProfileComplete(user) {
  return Boolean(cleanText(user?.full_name, 180) && cleanText(user?.father_name, 180) && isValidEmail(user?.email) && cleanText(user?.phone, 80));
}

function personFocusUrl(person) {
  return person?.id ? `/?focus=${encodeURIComponent(person.id)}` : "";
}

async function findTreePersonForSiteUser(user) {
  try {
    if (!user || !user.matched_person_id) return null;
    const direct = await get(`SELECT id, name, father_id, mother_id, photo_url, short_bio FROM persons WHERE id = ?`, [user.matched_person_id]);
    return direct || null;
  } catch (e) {
    console.error("findTreePersonForSiteUser error:", e.message || e);
  }
  return null;
}

async function findHonorForUser(user, person) {
  try {
    if (person?.id) {
      const byPerson = await get(`SELECT id, name FROM honor_items WHERE person_id = ? LIMIT 1`, [person.id]);
      if (byPerson) return byPerson;
    }
    const full = normalizeArabicForMatch(user?.full_name || "");
    if (!full) return null;
    const items = await all(`SELECT id, name FROM honor_items`);
    return items.find((item) => normalizeArabicForMatch(item.name) === full) || null;
  } catch (e) {
    return null;
  }
}

async function getSiteUserProfileStats(userId) {
  const id = Number(userId);
  const [activityCount, pageVisits, profileViews, uniqueViewers] = await Promise.all([
    get(`SELECT COUNT(*) AS total FROM site_user_activity_logs WHERE user_id = ?`, [id]).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM site_user_activity_logs WHERE user_id = ? AND action = 'زيارة صفحة'`, [id]).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM site_profile_views WHERE profile_user_id = ?`, [id]).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(DISTINCT viewer_user_id) AS total FROM site_profile_views WHERE profile_user_id = ? AND viewer_user_id IS NOT NULL`, [id]).catch(() => ({ total: 0 })),
  ]);
  return {
    activityCount: activityCount?.total || 0,
    pageVisits: pageVisits?.total || 0,
    profileViews: profileViews?.total || 0,
    uniqueViewers: uniqueViewers?.total || 0,
  };
}

async function logProfileView(req, profileUserId) {
  try {
    const viewerId = Number(req.session?.siteUser?.id || 0) || null;
    const profileId = Number(profileUserId || 0);
    if (!profileId || viewerId === profileId) return;
    const throttleKey = `profileView:${profileId}`;
    const now = Date.now();
    if (req.session[throttleKey] && now - Number(req.session[throttleKey]) < 10 * 60 * 1000) return;
    req.session[throttleKey] = now;
    await run(
      `INSERT INTO site_profile_views (profile_user_id, viewer_user_id, ip_address, user_agent, created_at)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [profileId, viewerId, getClientIp(req), String(req.headers["user-agent"] || "").slice(0, 300)]
    );
  } catch (e) {
    console.error("logProfileView error:", e.message || e);
  }
}

async function getSiteUserById(id) {
  return get(`SELECT * FROM site_users WHERE id = ?`, [id]);
}

async function getSiteUserByEmail(email) {
  const clean = String(email || "").trim().toLowerCase();
  if (!clean) return null;
  return get(`SELECT * FROM site_users WHERE LOWER(email) = ?`, [clean]);
}

function oauthStatus() {
  return {
    google: Boolean(passport && GoogleStrategy && process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
    passportInstalled: Boolean(passport),
  };
}

function getPublicBaseUrl() {
  const raw = process.env.PUBLIC_BASE_URL || process.env.SITE_URL || process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
  return String(raw || "").trim().replace(/\/+$/, "");
}

function absoluteOAuthCallbackUrl(provider = "google") {
  const envName = "GOOGLE_CALLBACK_URL";
  const fallbackPath = "/auth/google/callback";
  const value = String(process.env[envName] || "").trim();
  if (/^https?:\/\//i.test(value)) return value;
  const pathValue = value || fallbackPath;
  return `${getPublicBaseUrl()}${pathValue.startsWith("/") ? pathValue : `/${pathValue}`}`;
}

function envFlag(name, defaultValue = false) {
  const value = String(process.env[name] ?? "").trim().toLowerCase();
  if (!value) return Boolean(defaultValue);
  return ["1", "true", "yes", "on"].includes(value);
}

function newUserApprovalStatus(provider = "email") {
  if (envFlag("AUTO_APPROVE_NEW_USERS", false)) return "approved";
  if (provider !== "email" && envFlag("AUTO_APPROVE_OAUTH_USERS", true)) return "approved";
  return "pending";
}

function oauthLoginError(provider, err, info) {
  const providerName = "Google";
  const raw = String(err?.message || err?.oauthError?.data || err?.oauthError?.message || info?.message || "");
  console.error(`${providerName} OAuth failed:`, err || info || "unknown error");
  if (/invalid_client|unauthorized_client|client_secret/i.test(raw)) {
    return `فشل تسجيل الدخول عبر ${providerName}: Client Secret غير صحيح أو غير موجود في ملف .env.`;
  }
  if (/redirect_uri|redirect_uri_mismatch/i.test(raw)) {
    return `فشل تسجيل الدخول عبر ${providerName}: رابط الرجوع غير مطابق لما هو مسجل في Google Cloud.`;
  }
  if (/access_denied/i.test(raw)) {
    return `تم إلغاء تسجيل الدخول عبر ${providerName}.`;
  }
  if (/email/i.test(raw)) {
    return `فشل تسجيل الدخول عبر ${providerName}: لم يتم استلام البريد الإلكتروني من الحساب.`;
  }
  return `فشل تسجيل الدخول عبر ${providerName}. افتح التيرمنال لمعرفة السبب التفصيلي.`;
}

function rotateSessionPreservingAdmin(req) {
  return new Promise((resolve, reject) => {
    const preservedAdmin = req.session?.admin || null;
    const preservedOAuthNext = req.session?.oauthNext || null;
    req.session.regenerate((err) => {
      if (err) return reject(err);
      if (preservedAdmin) req.session.admin = preservedAdmin;
      if (preservedOAuthNext) req.session.oauthNext = preservedOAuthNext;
      resolve();
    });
  });
}

async function signInSiteUser(req, user) {
  await rotateSessionPreservingAdmin(req);
  req.session.siteUser = publicSiteUserSession(user);
  req.session.siteUserCheckedAt = Date.now();
}

function clearSiteUserSession(req) {
  delete req.session.siteUser;
  delete req.session.siteUserCheckedAt;
  delete req.session.oauthNext;
}

async function logSiteUserActivity(req, action, details = {}) {
  try {
    const user = req.session?.siteUser || null;
    if (!user?.id) return;
    await run(
      `INSERT INTO site_user_activity_logs
       (user_id, action, path, method, details, ip_address, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [
        user.id,
        cleanText(action, 120),
        cleanText(req.originalUrl || req.path || "", 500),
        cleanText(req.method || "GET", 20),
        JSON.stringify(details || {}),
        getClientIp(req),
        String(req.headers["user-agent"] || "").slice(0, 300),
      ]
    );
  } catch (e) {
    console.error("site user activity log error:", e.message || e);
  }
}

function maybeLogSiteVisit(req) {
  if (req.method !== "GET") return;
  if (isStaticLikePath(req.path)) return;
  if (req.path.startsWith("/image-thumb/") || req.path.startsWith("/uploads/")) return;
  const lastKey = `${req.method}:${req.originalUrl}`;
  const now = Date.now();
  if (req.session.lastSiteActivityKey === lastKey && now - Number(req.session.lastSiteActivityAt || 0) < 30 * 1000) return;
  req.session.lastSiteActivityKey = lastKey;
  req.session.lastSiteActivityAt = now;
  logSiteUserActivity(req, req.path.startsWith("/api/") ? "استخدام API" : "زيارة صفحة", {}).catch(() => {});
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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: "محاولات كثيرة. حاول بعد قليل.",
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

async function ensureSiteUsersTables() {
  await run(`
    CREATE TABLE IF NOT EXISTS site_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT,
      email TEXT UNIQUE,
      phone TEXT,
      country TEXT,
      city TEXT,
      password_hash TEXT,
      provider TEXT DEFAULT 'email',
      provider_id TEXT,
      avatar_url TEXT,
      is_active INTEGER DEFAULT 1,
      login_count INTEGER DEFAULT 0,
      last_login_at TEXT,
      last_seen_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const columns = await all(`PRAGMA table_info(site_users)`);
  const existing = new Set(columns.map((c) => c.name));
  const extras = [
    ["full_name", "TEXT"],
    ["father_name", "TEXT"],
    ["mother_name", "TEXT"],
    ["children_count", "INTEGER"],
    ["birth_date", "TEXT"],
    ["origin_place", "TEXT"],
    ["current_residence", "TEXT"],
    ["email", "TEXT"],
    ["phone", "TEXT"],
    ["phone_alt", "TEXT"],
    ["country", "TEXT"],
    ["city", "TEXT"],
    ["work", "TEXT"],
    ["qualification", "TEXT"],
    ["spouse_family", "TEXT"],
    ["spouse_name", "TEXT"],
    ["facebook_url", "TEXT"],
    ["instagram_url", "TEXT"],
    ["x_url", "TEXT"],
    ["linkedin_url", "TEXT"],
    ["matched_person_id", "INTEGER"],
    ["password_hash", "TEXT"],
    ["provider", "TEXT DEFAULT 'email'"],
    ["provider_id", "TEXT"],
    ["avatar_url", "TEXT"],
    ["cover_url", "TEXT"],
    ["avatar_pos_x", "REAL DEFAULT 50"],
    ["avatar_pos_y", "REAL DEFAULT 50"],
    ["cover_pos_x", "REAL DEFAULT 50"],
    ["cover_pos_y", "REAL DEFAULT 50"],
    ["chat_privacy", "TEXT DEFAULT 'all'"],
    ["profile_visibility", "TEXT DEFAULT 'members'"],
    ["show_phone", "INTEGER DEFAULT 1"],
    ["show_email", "INTEGER DEFAULT 1"],
    ["show_birth_date", "INTEGER DEFAULT 0"],
    ["show_social_links", "INTEGER DEFAULT 1"],
    ["approval_status", "TEXT DEFAULT 'approved'"],
    ["approved_by_admin_id", "INTEGER"],
    ["approved_at", "TEXT"],
    ["rejected_reason", "TEXT"],
    ["verification_status", "TEXT DEFAULT 'unverified'"],
    ["invite_code_used", "TEXT"],
    ["failed_login_count", "INTEGER DEFAULT 0"],
    ["locked_until", "TEXT"],
    ["is_active", "INTEGER DEFAULT 1"],
    ["login_count", "INTEGER DEFAULT 0"],
    ["last_login_at", "TEXT"],
    ["last_seen_at", "TEXT"],
    ["created_at", "TEXT"],
    ["updated_at", "TEXT"],
  ];
  for (const [name, definition] of extras) {
    if (!existing.has(name)) await ensureColumn("site_users", name, definition);
  }

  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_site_users_email ON site_users(LOWER(email)) WHERE email IS NOT NULL AND TRIM(email) <> ''`);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_users_provider ON site_users(provider, provider_id)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_users_approval ON site_users(approval_status, created_at)`).catch(() => {});
  await run(`UPDATE site_users SET approval_status='approved' WHERE approval_status IS NULL OR TRIM(approval_status)=''`).catch(() => {});
  await run(`UPDATE site_users SET verification_status='verified' WHERE matched_person_id IS NOT NULL AND (verification_status IS NULL OR verification_status='')`).catch(() => {});
  await run(`UPDATE site_users SET avatar_pos_x=50 WHERE avatar_pos_x IS NULL`).catch(() => {});
  await run(`UPDATE site_users SET avatar_pos_y=50 WHERE avatar_pos_y IS NULL`).catch(() => {});
  await run(`UPDATE site_users SET cover_pos_x=50 WHERE cover_pos_x IS NULL`).catch(() => {});
  await run(`UPDATE site_users SET cover_pos_y=50 WHERE cover_pos_y IS NULL`).catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS site_user_activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT,
      path TEXT,
      method TEXT,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_user_activity_user ON site_user_activity_logs(user_id, created_at)`);

  await run(`
    CREATE TABLE IF NOT EXISTS site_profile_views (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      profile_user_id INTEGER NOT NULL,
      viewer_user_id INTEGER,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_profile_views_profile ON site_profile_views(profile_user_id, created_at)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_profile_views_viewer ON site_profile_views(viewer_user_id, created_at)`);
}


/* =========================
   Chat helpers
   ========================= */
function chatDisplayName(user) {
  const full = cleanText(user?.full_name || user?.sender_name || "", 180);
  const father = cleanText(user?.father_name || "", 180);
  if (full && father && !full.includes(father)) return `${full} ${father}`;
  return full || cleanText(user?.email || "عضو العائلة", 180) || "عضو العائلة";
}

function chatAttachmentType(file) {
  const mime = String(file?.mimetype || "").toLowerCase();
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("audio/") || mime === "application/octet-stream") return "audio";
  return "file";
}

function emitChatThreadUpdate(threadId, event = "message", payload = {}) {
  try {
    if (!io || !threadId) return;
    io.to(`chat-thread:${Number(threadId)}`).emit("chat-thread-updated", { threadId: Number(threadId), event, ...payload });
  } catch (e) {}
}

async function getChatBannedWords() {
  const row = await get(`SELECT value FROM site_settings WHERE key='chat_banned_words'`).catch(() => null);
  const raw = String(row?.value || "");
  return raw.split(/[\n,،]+/).map((w) => cleanText(w, 80).trim()).filter(Boolean);
}

async function filterChatBody(body) {
  let text = cleanText(body || "", 2000);
  if (!text) return text;
  const words = await getChatBannedWords();
  for (const word of words) {
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (!escaped) continue;
    text = text.replace(new RegExp(escaped, "giu"), "***");
  }
  return text;
}

async function isUserChatBlocked(userId) {
  const uid = Number(userId || 0);
  if (!uid) return false;
  const row = await get(`SELECT id FROM site_chat_blocks WHERE user_id=? AND COALESCE(is_active,1)=1 LIMIT 1`, [uid]).catch(() => null);
  return Boolean(row);
}

async function canStartPrivateChat(senderId, receiverId) {
  const sid = Number(senderId || 0);
  const rid = Number(receiverId || 0);
  if (!sid || !rid || sid === rid) return { ok: false, message: "محادثة غير صحيحة" };
  if (await isUserChatBlocked(sid)) return { ok: false, message: "تم حظرك من استخدام الشات بواسطة الإدارة" };
  const receiver = await get(`SELECT id, chat_privacy, matched_person_id FROM site_users WHERE id=? AND COALESCE(is_active,1)=1`, [rid]).catch(() => null);
  if (!receiver) return { ok: false, message: "المستخدم غير موجود" };
  const privacy = receiver.chat_privacy || "all";
  if (privacy === "nobody") return { ok: false, message: "هذا العضو لا يستقبل رسائل خاصة حاليًا" };
  if (privacy === "linked_only") {
    const sender = await get(`SELECT id, matched_person_id FROM site_users WHERE id=? AND COALESCE(is_active,1)=1`, [sid]).catch(() => null);
    if (!sender?.matched_person_id || !receiver?.matched_person_id) {
      return { ok: false, message: "هذا العضو يستقبل الرسائل من الحسابات المرتبطة بالشجرة فقط" };
    }
  }
  return { ok: true };
}

async function archiveChatMessageBeforeDelete(messageId, adminId) {
  const msg = await get(`SELECT * FROM site_chat_messages WHERE id=?`, [messageId]).catch(() => null);
  if (!msg) return null;
  await run(
    `INSERT INTO site_chat_deleted_archive
     (original_message_id, thread_id, sender_user_id, body, message_type, attachment_url, attachment_name, attachment_mime, attachment_size, created_at, deleted_by_admin_id, deleted_at, raw_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`,
    [msg.id, msg.thread_id, msg.sender_user_id, msg.body || "", msg.message_type || "text", msg.attachment_url || "", msg.attachment_name || "", msg.attachment_mime || "", msg.attachment_size || 0, msg.created_at || null, adminId || null, JSON.stringify(msg)]
  ).catch(() => {});
  return msg;
}

async function ensurePublicChatThread() {
  let thread = await get(
    `SELECT * FROM site_chat_threads
     WHERE type='public' OR COALESCE(is_public,0)=1
     ORDER BY id ASC
     LIMIT 1`
  ).catch(() => null);

  if (thread) {
    await run(
      `UPDATE site_chat_threads
       SET type='public', is_public=1, title=COALESCE(NULLIF(title,''), 'الشات العام للعائلة')
       WHERE id=?`,
      [thread.id]
    ).catch(() => {});
    return get(`SELECT * FROM site_chat_threads WHERE id=?`, [thread.id]).catch(() => thread);
  }

  const result = await run(
    `INSERT INTO site_chat_threads
     (type, title, is_public, is_locked, is_active, created_at, updated_at)
     VALUES ('public', 'الشات العام للعائلة', 1, 0, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
  );
  return get(`SELECT * FROM site_chat_threads WHERE id=?`, [result.lastID]);
}

async function getPrivateThreadBetween(userA, userB) {
  const a = Number(userA || 0);
  const b = Number(userB || 0);
  if (!a || !b || a === b) return null;

  let thread = await get(
    `SELECT t.*
     FROM site_chat_threads t
     JOIN site_chat_participants p1 ON p1.thread_id=t.id AND p1.user_id=?
     JOIN site_chat_participants p2 ON p2.thread_id=t.id AND p2.user_id=?
     WHERE t.type='private'
     ORDER BY t.id ASC
     LIMIT 1`,
    [a, b]
  ).catch(() => null);

  if (thread) {
    if (Number(thread.is_active) !== 1) {
      await run(`UPDATE site_chat_threads SET is_active=1, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [thread.id]).catch(() => {});
      thread = await get(`SELECT * FROM site_chat_threads WHERE id=?`, [thread.id]).catch(() => thread);
    }
    await run(`INSERT OR IGNORE INTO site_chat_participants (thread_id, user_id, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, [thread.id, a]).catch(() => {});
    await run(`INSERT OR IGNORE INTO site_chat_participants (thread_id, user_id, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, [thread.id, b]).catch(() => {});
    return thread;
  }

  const result = await run(
    `INSERT INTO site_chat_threads
     (type, title, is_public, is_locked, is_active, created_by_user_id, created_at, updated_at)
     VALUES ('private', '', 0, 0, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
    [a]
  );
  const threadId = result.lastID;
  await run(`INSERT OR IGNORE INTO site_chat_participants (thread_id, user_id, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, [threadId, a]);
  await run(`INSERT OR IGNORE INTO site_chat_participants (thread_id, user_id, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, [threadId, b]);
  return get(`SELECT * FROM site_chat_threads WHERE id=?`, [threadId]);
}

async function userCanAccessThread(userId, threadId) {
  const uid = Number(userId || 0);
  const tid = Number(threadId || 0);
  if (!uid || !tid) return null;

  const thread = await get(`SELECT * FROM site_chat_threads WHERE id=?`, [tid]).catch(() => null);
  if (!thread || Number(thread.is_active) !== 1) return null;
  if (thread.type === "public" || Number(thread.is_public) === 1) return thread;

  const participant = await get(
    `SELECT id FROM site_chat_participants WHERE thread_id=? AND user_id=? LIMIT 1`,
    [tid, uid]
  ).catch(() => null);
  return participant ? thread : null;
}

async function unreadPrivateMessagesCount(userId) {
  const uid = Number(userId || 0);
  if (!uid) return 0;
  const row = await get(
    `SELECT COUNT(*) AS total
     FROM site_chat_messages m
     JOIN site_chat_threads t ON t.id=m.thread_id AND t.type='private' AND COALESCE(t.is_active,1)=1
     JOIN site_chat_participants p ON p.thread_id=m.thread_id AND p.user_id=?
     WHERE COALESCE(m.is_deleted,0)=0
       AND m.sender_user_id <> ?
       AND m.id > COALESCE(p.last_read_message_id,0)`,
    [uid, uid]
  ).catch(() => ({ total: 0 }));
  return Number(row?.total || 0);
}

async function serializeChatMessages(rows = [], options = {}) {
  const currentUserId = Number(options.currentUserId || 0);
  const threadId = Number(options.threadId || rows?.[0]?.thread_id || 0);
  let readByOthers = new Set();
  if (currentUserId && threadId) {
    const participantReads = await all(
      `SELECT user_id, COALESCE(last_read_message_id,0) AS last_read_message_id
       FROM site_chat_participants
       WHERE thread_id=? AND user_id <> ?`,
      [threadId, currentUserId]
    ).catch(() => []);
    for (const row of rows) {
      if (Number(row.sender_user_id) === currentUserId && participantReads.some((p) => Number(p.last_read_message_id || 0) >= Number(row.id))) {
        readByOthers.add(Number(row.id));
      }
    }
  }
  return rows
    .filter((row) => Number(row.is_deleted || 0) !== 1)
    .map((row) => ({
      id: row.id,
      thread_id: row.thread_id,
      sender_user_id: row.sender_user_id,
      sender_name: chatDisplayName({ full_name: row.sender_name, email: row.sender_email }),
      sender_avatar: row.sender_avatar || "/assets/default-avatar.svg",
      body: row.body || "",
      message_type: row.message_type || "text",
      attachment_url: row.attachment_url || "",
      attachment_name: row.attachment_name || "",
      attachment_mime: row.attachment_mime || "",
      attachment_size: row.attachment_size || 0,
      is_deleted: 0,
      edited_at: row.edited_at || "",
      created_at: row.created_at || "",
      read_by_others: readByOthers.has(Number(row.id)) ? 1 : 0,
    }));
}

async function ensureChatTables() {
  await run(`
    CREATE TABLE IF NOT EXISTS site_chat_threads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL DEFAULT 'private',
      title TEXT,
      is_public INTEGER DEFAULT 0,
      is_locked INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 1,
      created_by_user_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_threads_type ON site_chat_threads(type, is_active, updated_at)`);

  await run(`
    CREATE TABLE IF NOT EXISTS site_chat_participants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      thread_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      last_read_message_id INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(thread_id, user_id)
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_participants_user ON site_chat_participants(user_id, thread_id)`);

  await run(`
    CREATE TABLE IF NOT EXISTS site_chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      thread_id INTEGER NOT NULL,
      sender_user_id INTEGER,
      body TEXT,
      message_type TEXT DEFAULT 'text',
      attachment_url TEXT,
      attachment_name TEXT,
      attachment_mime TEXT,
      attachment_size INTEGER DEFAULT 0,
      is_deleted INTEGER DEFAULT 0,
      deleted_by_admin_id INTEGER,
      deleted_at TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_messages_thread ON site_chat_messages(thread_id, id)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_messages_sender ON site_chat_messages(sender_user_id, created_at)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_messages_deleted ON site_chat_messages(is_deleted, thread_id, id)`).catch(() => {});
  await run(`ALTER TABLE site_chat_messages ADD COLUMN edited_at TEXT`).catch(() => {});
  await run(`ALTER TABLE site_chat_messages ADD COLUMN edited_by_user_id INTEGER`).catch(() => {});
  await run(`ALTER TABLE site_chat_messages ADD COLUMN filtered_at TEXT`).catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS site_chat_blocks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      blocked_by_admin_id INTEGER,
      reason TEXT,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id)
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_blocks_user ON site_chat_blocks(user_id, is_active)`);

  await run(`
    CREATE TABLE IF NOT EXISTS site_chat_message_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id INTEGER NOT NULL,
      reporter_user_id INTEGER NOT NULL,
      reason TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by_admin_id INTEGER,
      reviewed_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_reports_message ON site_chat_message_reports(message_id, status)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_reports_reporter ON site_chat_message_reports(reporter_user_id, created_at)`);

  await run(`
    CREATE TABLE IF NOT EXISTS site_chat_deleted_archive (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      original_message_id INTEGER,
      thread_id INTEGER,
      sender_user_id INTEGER,
      body TEXT,
      message_type TEXT,
      attachment_url TEXT,
      attachment_name TEXT,
      attachment_mime TEXT,
      attachment_size INTEGER,
      created_at TEXT,
      deleted_by_admin_id INTEGER,
      deleted_at TEXT DEFAULT CURRENT_TIMESTAMP,
      raw_json TEXT
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_chat_archive_original ON site_chat_deleted_archive(original_message_id, deleted_at)`);

  const banned = await get(`SELECT key FROM site_settings WHERE key='chat_banned_words'`).catch(() => null);
  if (!banned) {
    await run(`INSERT INTO site_settings (key, value, updated_at) VALUES ('chat_banned_words', ?, CURRENT_TIMESTAMP)`, ["شتيمة\nإهانة"] ).catch(() => {});
  }

  await ensurePublicChatThread().catch(() => {});
}


async function ensureFamilyPlatformTables() {
  await run(`
    CREATE TABLE IF NOT EXISTS site_invite_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      note TEXT,
      max_uses INTEGER DEFAULT 1,
      used_count INTEGER DEFAULT 0,
      expires_at TEXT,
      is_active INTEGER DEFAULT 1,
      created_by_admin_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS site_user_tree_link_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      requested_person_id INTEGER,
      lineage_text TEXT,
      status TEXT DEFAULT 'pending',
      admin_note TEXT,
      reviewed_by_admin_id INTEGER,
      reviewed_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_tree_link_requests_status ON site_user_tree_link_requests(status, created_at)`).catch(() => {});
  await ensureColumn("site_user_tree_link_requests", "match_status", "TEXT").catch(() => {});
  await ensureColumn("site_user_tree_link_requests", "match_message", "TEXT").catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS site_notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT,
      body TEXT,
      url TEXT,
      type TEXT DEFAULT 'system',
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      read_at TEXT
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_notifications_user ON site_notifications(user_id, is_read, created_at)`).catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS site_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reporter_user_id INTEGER,
      target_type TEXT,
      target_id INTEGER,
      reason TEXT,
      details TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by_admin_id INTEGER,
      reviewed_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_reports_status ON site_reports(status, created_at)`).catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS family_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submitted_by_user_id INTEGER,
      title TEXT NOT NULL,
      event_type TEXT,
      event_date TEXT,
      location TEXT,
      description TEXT,
      image_url TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by_admin_id INTEGER,
      reviewed_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_family_events_status ON family_events(status, event_date)`).catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS family_gallery_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submitted_by_user_id INTEGER,
      title TEXT,
      category TEXT,
      image_url TEXT NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by_admin_id INTEGER,
      reviewed_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_family_gallery_status ON family_gallery_items(status, created_at)`).catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS tree_edit_suggestions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submitted_by_user_id INTEGER,
      person_id INTEGER,
      field_name TEXT,
      current_value TEXT,
      suggested_value TEXT,
      reason TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by_admin_id INTEGER,
      reviewed_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_tree_edit_suggestions_status ON tree_edit_suggestions(status, created_at)`).catch(() => {});

  await run(`
    CREATE TABLE IF NOT EXISTS tree_export_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      person_id INTEGER,
      person_name TEXT,
      export_title TEXT,
      export_options TEXT,
      persons_count INTEGER DEFAULT 0,
      generations_count INTEGER DEFAULT 0,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_tree_export_logs_created ON tree_export_logs(created_at)`).catch(() => {});
  await run(`CREATE INDEX IF NOT EXISTS idx_tree_export_logs_user ON tree_export_logs(user_id, created_at)`).catch(() => {});

  const settings = [
    ["require_invite_to_register", "0"],
    ["new_accounts_require_approval", "1"],
    ["profile_default_visibility", "members"],
  ];
  for (const [key, value] of settings) {
    const exists = await get(`SELECT key FROM site_settings WHERE key=?`, [key]).catch(() => null);
    if (!exists) await run(`INSERT INTO site_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, [key, value]);
  }
}

async function createNotification(userId, title, body = "", url = "", type = "system") {
  const uid = Number(userId || 0);
  if (!uid) return null;
  return run(
    `INSERT INTO site_notifications (user_id, title, body, url, type, is_read, created_at)
     VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
    [uid, cleanText(title, 180), cleanText(body, 500), cleanText(url, 500), cleanText(type, 80)]
  ).catch(() => null);
}

async function unreadNotificationsCount(userId) {
  const row = await get(`SELECT COUNT(*) AS total FROM site_notifications WHERE user_id=? AND COALESCE(is_read,0)=0`, [userId]).catch(() => ({ total: 0 }));
  return Number(row?.total || 0);
}

async function verifyInviteCode(code) {
  const clean = cleanText(code, 80).toUpperCase();
  const required = String((await get(`SELECT value FROM site_settings WHERE key='require_invite_to_register'`).catch(() => ({ value: "0" })))?.value || "0") === "1";
  if (!clean) return required ? { ok:false, message:"كود الدعوة مطلوب لإنشاء حساب داخل الموقع." } : { ok:true, code:"" };
  const invite = await get(`SELECT * FROM site_invite_codes WHERE UPPER(code)=? AND COALESCE(is_active,1)=1`, [clean]).catch(() => null);
  if (!invite) return { ok:false, message:"كود الدعوة غير صحيح أو غير مفعل." };
  if (invite.expires_at && new Date(invite.expires_at).getTime() < Date.now()) return { ok:false, message:"كود الدعوة منتهي الصلاحية." };
  if (Number(invite.max_uses || 0) > 0 && Number(invite.used_count || 0) >= Number(invite.max_uses || 0)) return { ok:false, message:"تم استخدام كود الدعوة للحد الأقصى." };
  return { ok:true, code: invite.code, invite };
}

async function consumeInviteCode(code) {
  if (!code) return;
  await run(`UPDATE site_invite_codes SET used_count=COALESCE(used_count,0)+1 WHERE code=?`, [code]).catch(() => {});
}

async function ensurePerformanceIndexes() {
  const indexes = [
    `CREATE INDEX IF NOT EXISTS idx_persons_father ON persons(father_id)`,
    `CREATE INDEX IF NOT EXISTS idx_persons_mother ON persons(mother_id)`,
    `CREATE INDEX IF NOT EXISTS idx_persons_name ON persons(name)`,
    `CREATE INDEX IF NOT EXISTS idx_site_users_email ON site_users(email)`,
    `CREATE INDEX IF NOT EXISTS idx_site_users_provider ON site_users(provider, provider_id)`,
    `CREATE INDEX IF NOT EXISTS idx_site_users_approval ON site_users(approval_status, is_active)`,
    `CREATE INDEX IF NOT EXISTS idx_site_users_last_seen ON site_users(last_seen_at)`,
    `CREATE INDEX IF NOT EXISTS idx_site_user_activity_user ON site_user_activity_logs(user_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_site_profile_views_profile ON site_profile_views(profile_user_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_site_profile_views_viewer ON site_profile_views(viewer_user_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_site_chat_participants_user ON site_chat_participants(user_id, thread_id)`,
    `CREATE INDEX IF NOT EXISTS idx_site_chat_messages_unread ON site_chat_messages(thread_id, sender_user_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_site_notifications_user_read ON site_notifications(user_id, is_read, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_person_requests_status_created ON person_requests(status, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_admin_activity_created ON admin_activity_logs(created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_tree_export_logs_person ON tree_export_logs(person_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_site_chat_messages_created_fast ON site_chat_messages(is_deleted, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_family_events_submitter_status ON family_events(submitted_by_user_id, status)`,
    `CREATE INDEX IF NOT EXISTS idx_family_gallery_submitter_status ON family_gallery_items(submitted_by_user_id, status)`,
  ];
  for (const sql of indexes) {
    await run(sql).catch((e) => console.warn("Index skipped:", e.message || e));
  }
}

async function bootstrap() {
  await ensurePersonsColumns();
  await ensureCmsTables();
  await ensureSpousesTable();
  await ensurePersonRequestsTable();
  await ensureAdminEnhancements();
  await ensureSiteUsersTables();
  await ensureChatTables();
  await ensureFamilyPlatformTables();
  await ensurePerformanceIndexes();
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
  const siteUsersRow = await get(`SELECT COUNT(*) AS total FROM site_users`).catch(() => ({ total: 0 }));
  const activeSiteUsersRow = await get(`SELECT COUNT(*) AS total FROM site_users WHERE COALESCE(is_active, 1)=1`).catch(() => ({ total: 0 }));
  const latestSiteUsers = await all(`SELECT id, full_name, email, provider, created_at, last_seen_at FROM site_users ORDER BY id DESC LIMIT 5`).catch(() => []);
  const maintenance = await get(`SELECT value FROM site_settings WHERE key='maintenance_enabled'`);
  const pagesTotalRow = await get(`SELECT COUNT(*) AS total FROM site_pages`).catch(() => ({ total: 0 }));
  const timelineTotalRow = await get(`SELECT COUNT(*) AS total FROM timeline_events`).catch(() => ({ total: 0 }));
  const chatMessagesTotalRow = await get(`SELECT COUNT(*) AS total FROM site_chat_messages WHERE COALESCE(is_deleted,0)=0`).catch(() => ({ total: 0 }));
  const treeExportsTotalRow = await get(`SELECT COUNT(*) AS total FROM tree_export_logs`).catch(() => ({ total: 0 }));
  const pendingUsersRow = await get(`SELECT COUNT(*) AS total FROM site_users WHERE COALESCE(approval_status,'approved')='pending'`).catch(() => ({ total: 0 }));
  const pendingLinkRequestsRow = await get(`SELECT COUNT(*) AS total FROM site_user_tree_link_requests WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 }));
  const pendingReportsRow = await get(`SELECT COUNT(*) AS total FROM site_reports WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 }));
  const pendingEventsRow = await get(`SELECT COUNT(*) AS total FROM family_events WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 }));
  const pendingGalleryRow = await get(`SELECT COUNT(*) AS total FROM family_gallery_items WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 }));
  const pendingSuggestionsRow = await get(`SELECT COUNT(*) AS total FROM tree_edit_suggestions WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 }));
  const pendingApprovalsTotal = [pendingUsersRow, pendingLinkRequestsRow, pendingReportsRow, pendingEventsRow, pendingGalleryRow, pendingSuggestionsRow]
    .reduce((sum, row) => sum + Number(row?.total || 0), 0);
  return {
    stats,
    latestPersons,
    latestNews,
    latestSupport,
    latestActivity,
    siteUsersTotal: Number(siteUsersRow?.total || 0),
    activeSiteUsers: Number(activeSiteUsersRow?.total || 0),
    latestSiteUsers,
    pagesTotal: Number(pagesTotalRow?.total || 0),
    timelineTotal: Number(timelineTotalRow?.total || 0),
    chatMessagesTotal: Number(chatMessagesTotalRow?.total || 0),
    treeExportsTotal: Number(treeExportsTotalRow?.total || 0),
    pendingApprovalsTotal,
    maintenanceEnabled: String(maintenance?.value || "0") === "1",
  };
}

async function getAdminPendingCounts() {
  const [pendingUsers, linkRequests, reports, events, gallery, suggestions, support, personRequests] = await Promise.all([
    get(`SELECT COUNT(*) AS total FROM site_users WHERE COALESCE(approval_status,'approved')='pending'`).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM site_user_tree_link_requests WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM site_reports WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM family_events WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM family_gallery_items WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM tree_edit_suggestions WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM support_messages`).catch(() => ({ total: 0 })),
    get(`SELECT COUNT(*) AS total FROM person_requests WHERE COALESCE(status,'pending')='pending'`).catch(() => ({ total: 0 })),
  ]);
  const approvalsTotal = [pendingUsers, linkRequests, reports, events, gallery, suggestions]
    .reduce((sum, row) => sum + Number(row?.total || 0), 0);
  return {
    pendingUsers: Number(pendingUsers?.total || 0),
    linkRequests: Number(linkRequests?.total || 0),
    reports: Number(reports?.total || 0),
    events: Number(events?.total || 0),
    gallery: Number(gallery?.total || 0),
    suggestions: Number(suggestions?.total || 0),
    support: Number(support?.total || 0),
    personRequests: Number(personRequests?.total || 0),
    approvalsTotal,
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

async function getAdminPersonOptions() {
  return all(`
    SELECT id, name, father_id, mother_id, gender, photo_url
    FROM persons
    ORDER BY name COLLATE NOCASE ASC, id ASC
    LIMIT 5000
  `).catch(() => []);
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


function publicPersonForExport(person) {
  if (!person) return null;
  return {
    id: Number(person.id || 0),
    name: person.name || "",
    father_id: person.father_id ? Number(person.father_id) : null,
    mother_id: person.mother_id ? Number(person.mother_id) : null,
    gender: person.gender || "",
    photo_url: person.photo_url || "",
    job: person.job || "",
    birth_date: person.birth_date || "",
    lineage_label: person.lineage_label || "",
  };
}

function safeExportDepth(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  if (raw === "all" || raw === "كل" || raw === "all-generations") return 99;
  const n = Number(raw || 0);
  if (!Number.isFinite(n) || n <= 0) return 99;
  return Math.min(Math.max(Math.floor(n), 1), 12);
}


function makeExportChildrenIndex(rows, mode = "both") {
  const byParent = new Map();

  function add(parentId, child) {
    const pid = Number(parentId || 0);
    if (!pid) return;
    if (!byParent.has(pid)) byParent.set(pid, []);
    byParent.get(pid).push(child);
  }

  for (const p of rows || []) {
    if (mode === "primary") {
      // في المخطط الكامل نضع الشخص مرة واحدة فقط تحت الأب إن وجد، وإلا تحت الأم.
      add(p.father_id || p.mother_id, p);
    } else {
      // في إصدار فرع شخص معيّن نسمح بظهور الأبناء سواء كان الشخص أبًا أو أمًا.
      add(p.father_id, p);
      add(p.mother_id, p);
    }
  }

  for (const list of byParent.values()) {
    list.sort((a, b) => Number(a.id || 0) - Number(b.id || 0));
  }
  return byParent;
}

function prepareExportNode(person, depth, includePhotos) {
  const payload = publicPersonForExport(person);
  if (!includePhotos) payload.photo_url = "";
  payload.level = depth;
  return payload;
}

function buildBranchExportTree(root, rows, options = {}) {
  // السلوك الاحتياطي القديم: الشخص + ذريته فقط.
  const maxDepth = safeExportDepth(options.maxDepth || options.generations || 99);
  const includePhotos = options.includePhotos !== false;
  const byParent = makeExportChildrenIndex(rows, "both");
  const seen = new Set();
  let count = 0;
  let maxLevel = 0;

  function walk(person, depth) {
    const id = Number(person?.id || 0);
    if (!person || !id || seen.has(id) || depth > maxDepth) return null;
    seen.add(id);
    count += 1;
    maxLevel = Math.max(maxLevel, depth);
    const payload = prepareExportNode(person, depth, includePhotos);
    const children = depth >= maxDepth ? [] : (byParent.get(id) || []).map((child) => walk(child, depth + 1)).filter(Boolean);
    payload.children = children;
    payload.children_count = children.length;
    return payload;
  }

  const tree = walk(root, 0);
  return { tree, count, generations: maxLevel + 1 };
}

function buildLineageBranchExportTree(root, rows, options = {}) {
  // المطلوب عند إصدار اسم محدد: آخر جد ← الأجداد ← الأب ← الشخص ← كل ذريته حسب اختيار الأجيال.
  const maxDescendantDepth = safeExportDepth(options.maxDepth || options.generations || 99);
  const includePhotos = options.includePhotos !== false;
  const byId = new Map((rows || []).map((r) => [Number(r.id), { ...r, id: Number(r.id) }]));
  const byParent = makeExportChildrenIndex(rows, "both");
  const lineage = [];
  const seenLineage = new Set();

  let current = root;
  while (current && current.id && !seenLineage.has(Number(current.id))) {
    lineage.unshift(current);
    seenLineage.add(Number(current.id));
    current = current.father_id ? byId.get(Number(current.father_id)) : null;
  }

  if (!lineage.length) lineage.push(root);

  const seen = new Set();
  let count = 0;
  let maxLevel = 0;

  function register(person, absoluteDepth) {
    const id = Number(person?.id || 0);
    if (!person || !id || seen.has(id)) return null;
    seen.add(id);
    count += 1;
    maxLevel = Math.max(maxLevel, absoluteDepth);
    return prepareExportNode(person, absoluteDepth, includePhotos);
  }

  function buildDescendants(person, absoluteDepth, descendantDepth) {
    const payload = register(person, absoluteDepth);
    if (!payload) return null;
    const id = Number(person.id);
    const children = descendantDepth >= maxDescendantDepth
      ? []
      : (byParent.get(id) || [])
          .map((child) => buildDescendants(child, absoluteDepth + 1, descendantDepth + 1))
          .filter(Boolean);
    payload.children = children;
    payload.children_count = children.length;
    return payload;
  }

  function buildLineageAt(index, absoluteDepth) {
    const person = lineage[index];
    const payload = register(person, absoluteDepth);
    if (!payload) return null;

    let children = [];
    if (index < lineage.length - 1) {
      const next = buildLineageAt(index + 1, absoluteDepth + 1);
      if (next) children.push(next);
    } else {
      const id = Number(person.id);
      children = (byParent.get(id) || [])
        .map((child) => buildDescendants(child, absoluteDepth + 1, 1))
        .filter(Boolean);
    }

    payload.children = children;
    payload.children_count = children.length;
    return payload;
  }

  const tree = buildLineageAt(0, 0);
  return { tree, count, generations: maxLevel + 1, ancestorsCount: lineage.length - 1 };
}

function buildFullTreeExport(rows, options = {}) {
  // إصدار الشجرة كاملة يعني كل فرد موجود في جدول persons بلا استثناء.
  // تحسين الأداء: نرجع أيضًا قائمة مسطحة flatPersons لاستخدامها في المعاينة والطباعة السريعة، بدل رسم UL متداخل ضخم جدًا.
  const includePhotos = options.includePhotos !== false;
  const normalizedRows = (rows || []).map((r) => ({ ...r, id: Number(r.id) })).filter((r) => Number(r.id));
  const byId = new Map(normalizedRows.map((r) => [Number(r.id), r]));
  const byParent = makeExportChildrenIndex(normalizedRows, "primary");
  const seen = new Set();
  const flatPersons = [];
  let maxLevel = 0;

  function primaryParentId(person) {
    const fatherId = Number(person?.father_id || 0);
    const motherId = Number(person?.mother_id || 0);
    if (fatherId && byId.has(fatherId)) return fatherId;
    if (motherId && byId.has(motherId)) return motherId;
    return 0;
  }

  let roots = normalizedRows.filter((p) => !primaryParentId(p));
  roots.sort((a, b) => Number(a.id || 0) - Number(b.id || 0));

  function flatPayload(person, depth) {
    const id = Number(person?.id || 0);
    const rawChildren = byParent.get(id) || [];
    const payload = prepareExportNode(person, depth, includePhotos);
    payload.primary_parent_id = primaryParentId(person) || null;
    payload.children_count = rawChildren.length;
    payload.has_photo = Boolean(payload.photo_url);
    return payload;
  }

  function walk(person, depth) {
    const id = Number(person?.id || 0);
    if (!person || !id || seen.has(id)) return null;
    seen.add(id);
    maxLevel = Math.max(maxLevel, depth);
    flatPersons.push(flatPayload(person, depth));

    const payload = prepareExportNode(person, depth, includePhotos);
    const children = (byParent.get(id) || []).map((child) => walk(child, depth + 1)).filter(Boolean);
    payload.children = children;
    payload.children_count = children.length;
    return payload;
  }

  const forest = roots.map((root) => walk(root, 0)).filter(Boolean);

  // ضمان إدراج أي أفراد لم يظهروا بسبب دورات/علاقات أبوة غير سليمة/بيانات منفصلة.
  const detached = normalizedRows
    .filter((person) => !seen.has(Number(person.id)))
    .sort((a, b) => Number(a.id || 0) - Number(b.id || 0))
    .map((person) => walk(person, 0))
    .filter(Boolean);

  flatPersons.sort((a, b) => Number(a.level || 0) - Number(b.level || 0) || Number(a.id || 0) - Number(b.id || 0));

  const allRoots = [...forest, ...detached];
  const tree = {
    id: 0,
    name: "الشجرة كاملة",
    father_id: null,
    mother_id: null,
    gender: "",
    photo_url: "",
    job: "",
    birth_date: "",
    lineage_label: "كل الأسماء المسجلة داخل الشجرة التفاعلية",
    level: 0,
    is_virtual_root: true,
    children: allRoots,
    children_count: allRoots.length,
  };

  return {
    tree,
    persons: flatPersons,
    count: normalizedRows.length,
    generations: maxLevel + 1,
    rootsCount: allRoots.length,
    includedAllPersons: true,
    detachedRootsCount: detached.length,
  };
}

async function findExportPersonCandidates(query) {
  const { rows, byId } = await getPersonsForRelationship();
  const matched = matchPersonByFlexibleName(query, rows, byId);
  return {
    status: matched.status,
    candidates: (matched.matches || []).slice(0, 12).map((p) => ({
      id: Number(p.id),
      name: p.name,
      photo_url: p.photo_url || "",
      lineage_label: p.lineage_label || lineagePhraseForPerson(p, byId, 4),
      father_id: p.father_id || null,
      mother_id: p.mother_id || null,
      gender: p.gender || "",
      match_score: p.match_score || 0,
    })),
  };
}

function ancestorMap(person, byId, maxDepth = 30) {
  const map = new Map();
  const visiting = new Set();
  function walk(node, dist, path) {
    const id = Number(node?.id || 0);
    if (!node || !id || dist > maxDepth || visiting.has(id)) return;
    const existing = map.get(id);
    if (existing && existing.distance <= dist) return;
    visiting.add(id);
    map.set(id, { person: node, distance: dist, path: [...path, node] });
    const father = node.father_id ? byId.get(Number(node.father_id)) : null;
    const mother = node.mother_id ? byId.get(Number(node.mother_id)) : null;
    if (father) walk(father, dist + 1, [...path, node]);
    if (mother) walk(mother, dist + 1, [...path, node]);
    visiting.delete(id);
  }
  walk(person, 0, []);
  return map;
}

function personPathText(path) {
  return path.map((p)=>p.name).join(" ← ");
}

function uniquePeoplePath(path) {
  const seen = new Set();
  const out = [];
  for (const p of path || []) {
    const id = Number(p?.id || 0);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(p);
  }
  return out;
}

function buildKinshipGraph(a, b, best) {
  const chainA = uniquePeoplePath(best?.a?.path || []);
  const chainB = uniquePeoplePath(best?.b?.path || []);
  const common = best?.common || chainA[chainA.length - 1] || chainB[chainB.length - 1];
  if (!a || !b || !common) return null;

  const commonId = Number(common.id);
  const branchA = uniquePeoplePath(chainA.slice().reverse());
  const branchB = uniquePeoplePath(chainB.slice().reverse());
  const hasA = branchA.length > 1;
  const hasB = branchB.length > 1;
  const leftX = hasA && hasB ? -220 : 0;
  const rightX = hasA && hasB ? 220 : 0;
  const levelGap = 145;
  const topY = 70;
  const nodeMap = new Map();
  const edgesMap = new Map();

  function nodeRole(p) {
    const id = Number(p.id);
    if (id === Number(a.id) && id === Number(b.id)) return "both";
    if (id === Number(a.id)) return "person_a";
    if (id === Number(b.id)) return "person_b";
    if (id === commonId) return "common";
    return "connector";
  }

  function addNode(p, x, y) {
    if (!p?.id) return;
    const id = Number(p.id);
    const existing = nodeMap.get(id);
    const payload = {
      id,
      name: p.name || "",
      photo_url: p.photo_url || "",
      gender: p.gender || "",
      focus_url: `/?focus=${encodeURIComponent(id)}`,
      role: nodeRole(p),
      x,
      y,
    };
    if (!existing) nodeMap.set(id, payload);
    else {
      existing.x = Math.round((Number(existing.x || 0) + x) / 2);
      existing.y = Math.min(Number(existing.y || y), y);
      if (existing.role === "connector") existing.role = payload.role;
    }
  }

  function addEdge(parent, child) {
    if (!parent?.id || !child?.id) return;
    const from = Number(parent.id);
    const to = Number(child.id);
    if (from === to) return;
    edgesMap.set(`${from}-${to}`, { from, to });
  }

  addNode(common, 0, topY);
  function layBranch(branch, x) {
    for (let i = 0; i < branch.length; i++) {
      const p = branch[i];
      addNode(p, i === 0 ? 0 : x, topY + (i * levelGap));
      if (i > 0) addEdge(branch[i - 1], p);
    }
  }
  layBranch(branchA, leftX);
  layBranch(branchB, rightX);

  const nodes = Array.from(nodeMap.values()).sort((x, y) => Number(x.y) - Number(y.y) || Number(x.x) - Number(y.x));
  const maxY = nodes.reduce((m, n) => Math.max(m, Number(n.y || 0)), topY);
  const minX = nodes.reduce((m, n) => Math.min(m, Number(n.x || 0)), 0);
  const maxX = nodes.reduce((m, n) => Math.max(m, Number(n.x || 0)), 0);
  return {
    nodes,
    edges: Array.from(edgesMap.values()),
    commonAncestor: { id: commonId, name: common.name || "" },
    personA: { id: Number(a.id), name: a.name || "" },
    personB: { id: Number(b.id), name: b.name || "" },
    viewBox: {
      x: Math.min(minX - 190, -420),
      y: 0,
      width: Math.max(maxX - minX + 380, 840),
      height: Math.max(maxY + 160, 380),
    },
  };
}

function describeKinship(a, b, byId) {
  if (!a || !b) return { ok:false, message:"لم يتم العثور على أحد الشخصين." };
  if (Number(a.id) === Number(b.id)) {
    const graph = {
      nodes: [{ id:Number(a.id), name:a.name || "", photo_url:a.photo_url || "", gender:a.gender || "", focus_url:`/?focus=${encodeURIComponent(a.id)}`, role:"both", x:0, y:90 }],
      edges: [],
      commonAncestor: { id:Number(a.id), name:a.name || "" },
      personA: { id:Number(a.id), name:a.name || "" },
      personB: { id:Number(b.id), name:b.name || "" },
      viewBox: { x:-260, y:0, width:520, height:280 },
    };
    return { ok:true, message:`${a.name} و ${b.name} هما نفس الشخص داخل الشجرة.`, path:[{ id:a.id, name:a.name, photo_url:a.photo_url || "", gender:a.gender || "" }], commonAncestor:{ id:a.id, name:a.name }, graph };
  }

  const aAnc = ancestorMap(a, byId);
  const bAnc = ancestorMap(b, byId);
  let best = null;
  for (const [id, va] of aAnc.entries()) {
    const vb = bAnc.get(id);
    if (!vb) continue;
    const total = va.distance + vb.distance;
    const maxDistance = Math.max(va.distance, vb.distance);
    if (!best || total < best.total || (total === best.total && maxDistance < best.maxDistance)) best = { id, common: va.person, a: va, b: vb, total, maxDistance };
  }

  if (!best) {
    return {
      ok:false,
      code:"NO_COMMON_ANCESTOR",
      message:"لا توجد صلة قرابة واضحة بين الاسمين داخل البيانات الحالية للشجرة. قد يكون أحد فروع الأب أو الأم غير مكتمل في قاعدة البيانات.",
      suggestions:["راجع كتابة الاسم كاملًا", "جرّب الاسم الرباعي", "تأكد من وجود الأب أو الأم داخل الشجرة"]
    };
  }
  const dA = best.a.distance;
  const dB = best.b.distance;
  const common = best.common;
  const fullPath = uniquePeoplePath([...best.a.path, ...best.b.path.slice(0, -1).reverse()].filter(Boolean));
  const graph = buildKinshipGraph(a, b, best);

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
    path: fullPath.map((p)=>({ id:p.id, name:p.name, photo_url:p.photo_url || "", gender:p.gender || "" })),
    commonAncestor: { id: common.id, name: common.name },
    graph,
  };
}

function kinshipCandidatePayload(matches) {
  return (matches || []).slice(0, 8).map((x) => ({
    id: Number(x.id),
    name: x.name || "",
    lineage_label: x.lineage_label || "",
    photo_url: x.photo_url || "",
    focus_url: `/?focus=${encodeURIComponent(x.id)}`,
  }));
}

async function calculateKinshipByNames(personA, personB) {
  const cleanA = cleanText(personA, 220);
  const cleanB = cleanText(personB, 220);
  if (!cleanA || !cleanB) return { ok:false, code:"MISSING_NAMES", message:"اكتب اسم الشخصين أولًا لحساب صلة القرابة." };
  if (normalizeArabicForMatch(cleanA) === normalizeArabicForMatch(cleanB)) {
    return { ok:false, code:"SAME_QUERY", message:"الاسمان المكتوبان متطابقان. اكتب اسمين مختلفين، أو افتح موقع الشخص مباشرة من الشجرة." };
  }
  const { rows, byId } = await getPersonsForRelationship();
  const aMatch = matchPersonByFlexibleName(cleanA, rows, byId);
  const bMatch = matchPersonByFlexibleName(cleanB, rows, byId);
  if (aMatch.status !== "matched") {
    if (aMatch.status === "multiple") return { ok:false, code:"MULTIPLE_A", field:"person_a", message:`يوجد أكثر من شخص مطابق للاسم الأول. اكتب الاسم رباعي أو أضف اسم الأب/الجد بدقة.
النتائج المحتملة: ${aMatch.matches.map(x=>`${x.name} (${x.lineage_label})`).join("، ")}`, candidates: kinshipCandidatePayload(aMatch.matches) };
    return { ok:false, code:"NOT_FOUND_A", field:"person_a", message:"لم يتم العثور على الشخص الأول داخل الشجرة. برجاء كتابة الاسم ثلاثي أو رباعي.", suggestions:["اكتب الاسم بدون ألقاب", "جرّب اسم الأب والجد", "تأكد من أن الشخص موجود في الشجرة"] };
  }
  if (bMatch.status !== "matched") {
    if (bMatch.status === "multiple") return { ok:false, code:"MULTIPLE_B", field:"person_b", message:`يوجد أكثر من شخص مطابق للاسم الثاني. اكتب الاسم رباعي أو أضف اسم الأب/الجد بدقة.
النتائج المحتملة: ${bMatch.matches.map(x=>`${x.name} (${x.lineage_label})`).join("، ")}`, candidates: kinshipCandidatePayload(bMatch.matches) };
    return { ok:false, code:"NOT_FOUND_B", field:"person_b", message:"لم يتم العثور على الشخص الثاني داخل الشجرة. برجاء كتابة الاسم ثلاثي أو رباعي.", suggestions:["اكتب الاسم بدون ألقاب", "جرّب اسم الأب والجد", "تأكد من أن الشخص موجود في الشجرة"] };
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
    ],
    memory: makePersonConversationMemory(person, rows)
  };
}


function makePersonConversationMemory(person, rows) {
  const children = rows
    .filter((x) => Number(x.father_id) === Number(person.id) || Number(x.mother_id) === Number(person.id))
    .map((c) => ({ id: c.id, name: c.name, gender: c.gender || "" }));
  return {
    lastPersonId: person.id,
    lastPersonName: person.name,
    lastChildren: children,
    lastChildrenNames: children.map((c) => c.name),
  };
}

function stripContextChildNoise(question) {
  let q = cleanText(String(question || ""), 300);
  q = q
    .replace(/[؟?]/g, " ")
    .replace(/^(?:ممكن\s+)?(?:معلومات\s+عن|تفاصيل\s+عن|بيانات\s+عن|نبذه\s+عن|نبذة\s+عن|مين\s+هي|مين\s+هو|من\s+هي|من\s+هو|وريني|اعرض|هات\s+لي|هاتلي|افتح|شوف|ابحث\s+عن|ابحث\s+على|ابحث\s+علي|دورلي\s+على|دورلي\s+علي|show\s+me|find|search\s+for)\s+/i, "")
    .replace(/\b(?:بنته|بنت\s+ه|بنتة|ابنته|ابنتة|ابنته|ابنه|ابن\s+ه|ولده|ولد\s+ه|عياله|ابنائه|ابناءه|أبنائه|أبناءه|بناته|ولاده|اولاده|أولاده)\b/gi, " ")
    .replace(/\b(?:اللي|التي|الذي|اسمها|اسمه|اسمها\s+هو|اسمه\s+هو|اسم)\b/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  return stripAssistantNameNoise(q);
}

async function answerPersonFromConversationContext(question, context = {}) {
  const children = Array.isArray(context.lastChildren) ? context.lastChildren : [];
  if (!children.length) return null;

  const cleaned = stripContextChildNoise(question);
  const queryNorm = normalizeArabicForMatch(cleaned);
  const rawNorm = normalizeArabicForMatch(question);
  if (!queryNorm && !rawNorm) return null;

  const relationWords = ["بنته", "بنت", "ابنته", "ابنه", "ولده", "ولد", "عياله", "ابناء", "أبناء", "اولاده", "أولاده", "بناته"];
  const looksContextual = relationWords.some((w) => rawNorm.includes(normalizeArabicForMatch(w))) ||
    ["معلومات", "تفاصيل", "وريني", "اعرض", "هات", "مين", "من هو", "من هي", "show", "find"].some((w) => rawNorm.includes(normalizeArabicForMatch(w)));

  let matches = [];
  for (const child of children) {
    const childNorm = normalizeArabicForMatch(child.name || "");
    const childParts = childNorm.split(" ").filter(Boolean);
    const first = childParts[0] || "";
    if (!childNorm) continue;

    if (queryNorm && (childNorm === queryNorm || childNorm.includes(queryNorm) || queryNorm.includes(childNorm))) {
      matches.push(child);
      continue;
    }
    if (first && queryNorm && (first === queryNorm || queryNorm.split(" ").includes(first))) {
      matches.push(child);
      continue;
    }
    if (looksContextual && first && rawNorm.includes(first)) {
      matches.push(child);
      continue;
    }
  }

  matches = matches.filter((x, i, arr) => arr.findIndex((y) => Number(y.id) === Number(x.id)) === i);
  if (!matches.length) return null;

  const { rows, byId } = await getPersonsForRelationship();
  if (matches.length === 1) {
    const person = byId.get(Number(matches[0].id));
    if (!person) return null;
    const result = await buildPersonAssistantAnswer(person, rows, byId);
    result.answer = `تمام، فهمت إنك تقصد ${person.name} من أبناء ${context.lastPersonName || "آخر شخص تم ذكره"}.\n` + result.answer;
    result.memory = makePersonConversationMemory(person, rows);
    return result;
  }

  return {
    answer: `وجدت أكثر من ابن/ابنة مطابقين من أبناء ${context.lastPersonName || "آخر شخص"}. اختر المقصود أو اكتب الاسم أوضح:\n${matches.map((x, i) => `${i + 1}- ${x.name}`).join("\n")}`,
    actions: matches.map((x) => ({ label: `عرض ${x.name}`, url: `/?focus=${x.id}` })).slice(0, 10),
    memory: {
      lastPersonId: context.lastPersonId,
      lastPersonName: context.lastPersonName,
      lastChildren: children,
      lastChildrenNames: children.map((c) => c.name),
    }
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

  const dictionaryAnswer = await answerFromAssistantKnowledge(q);
  if (dictionaryAnswer) return dictionaryAnswer;

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
   Site User Auth + OAuth
   ========================= */

async function createOrUpdateOAuthUser(provider, profile) {
  const emails = profile?.emails || [];
  const email = String(emails[0]?.value || profile?.email || "").trim().toLowerCase();
  const providerId = String(profile?.id || profile?.sub || "").trim();
  const fullName = cleanText(profile?.displayName || [profile?.name?.givenName, profile?.name?.familyName].filter(Boolean).join(" ") || email.split("@")[0] || "مستخدم الموقع", 180);
  const avatar = profile?.photos?.[0]?.value || "";

  let user = email ? await getSiteUserByEmail(email) : null;
  if (!user && providerId) {
    user = await get(`SELECT * FROM site_users WHERE provider = ? AND provider_id = ? LIMIT 1`, [provider, providerId]);
  }

  if (user) {
    await run(
      `UPDATE site_users
       SET provider = COALESCE(NULLIF(provider, ''), ?),
           provider_id = COALESCE(NULLIF(provider_id, ''), ?),
           full_name = CASE WHEN TRIM(COALESCE(full_name, '')) = '' THEN ? ELSE full_name END,
           avatar_url = CASE WHEN ? <> '' THEN ? ELSE avatar_url END,
           is_active = COALESCE(is_active, 1),
           login_count = COALESCE(login_count, 0) + 1,
           last_login_at = CURRENT_TIMESTAMP,
           last_seen_at = CURRENT_TIMESTAMP,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [provider, providerId, fullName, avatar, avatar, user.id]
    );
    return getSiteUserById(user.id);
  }

  if (!email) throw new Error("لم يرجع مزود الدخول بريدًا إلكترونيًا صالحًا");

  const approvalStatus = newUserApprovalStatus(provider);
  const result = await run(
    `INSERT INTO site_users
     (full_name, email, provider, provider_id, avatar_url, approval_status, is_active, login_count, last_login_at, last_seen_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
    [fullName, email, provider, providerId, avatar, approvalStatus]
  );
  return getSiteUserById(result.lastID);
}

function configurePassportStrategies() {
  if (!passport) return;
  passport.serializeUser((user, done) => done(null, user?.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await getSiteUserById(id);
      done(null, user || false);
    } catch (e) {
      done(e);
    }
  });

  const status = oauthStatus();
  if (status.google) {
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: absoluteOAuthCallbackUrl("google"),
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        const user = await createOrUpdateOAuthUser("google", profile);
        return done(null, user);
      } catch (e) {
        return done(e);
      }
    }));
  }

  
}
configurePassportStrategies();

function renderUserAuth(res, options = {}) {
  return res.render("user_auth", {
    mode: options.mode || "login",
    error: options.error || null,
    success: options.success || null,
    nextUrl: safeRedirectUrl(options.nextUrl || "/"),
    values: options.values || {},
    oauth: oauthStatus(),
  });
}

app.get("/auth/status", (req, res) => {
  res.json({
    ok: true,
    passportInstalled: oauthStatus().passportInstalled,
    googleEnabled: oauthStatus().google,
    autoApproveNewUsers: envFlag("AUTO_APPROVE_NEW_USERS", false),
    autoApproveOAuthUsers: envFlag("AUTO_APPROVE_OAUTH_USERS", true),
    publicBaseUrl: getPublicBaseUrl(),
    googleCallbackUrl: absoluteOAuthCallbackUrl("google"),
  });
});

app.get("/login", (req, res) => {
  if (req.session?.siteUser?.id) return res.redirect(safeRedirectUrl(req.query.next || "/"));
  renderUserAuth(res, { mode: "login", error: req.query.error || null, success: req.query.success || null, nextUrl: req.query.next || "/" });
});

app.get("/register", (req, res) => {
  if (req.session?.siteUser?.id) return res.redirect(safeRedirectUrl(req.query.next || "/"));
  renderUserAuth(res, { mode: "register", error: req.query.error || null, nextUrl: req.query.next || "/" });
});

app.post("/register", loginLimiter, profileImageUploadHandler("/register"), async (req, res) => {
  try {
    const fields = extractSiteUserProfileFields(req.body);
    const password = String(req.body.password || "");
    const nextUrl = safeRedirectUrl(req.body.next || "/account");
    const inviteCheck = await verifyInviteCode(req.body.invite_code || "");
    if (!inviteCheck.ok) {
      await removeUploadedFilesFromRequest(req.files);
      return renderUserAuth(res, { mode: "register", error: inviteCheck.message, nextUrl, values: fields });
    }

    const profileImageSizeError = validateProfileImageSizes(req.files);
    if (profileImageSizeError) {
      await removeUploadedFilesFromRequest(req.files);
      return renderUserAuth(res, { mode: "register", error: profileImageSizeError, nextUrl, values: fields });
    }

    const avatarFile = req.files?.avatar_file?.[0] || null;
    const coverFile = req.files?.cover_file?.[0] || null;
    const avatarUrl = avatarFile ? `/uploads/${avatarFile.filename}` : "";
    const coverUrl = coverFile ? `/uploads/${coverFile.filename}` : "";

    if (!fields.full_name || !fields.father_name || !isValidEmail(fields.email) || !fields.phone || password.length < 6) {
      await removeUploadedFilesFromRequest(req.files);
      return renderUserAuth(res, {
        mode: "register",
        error: "البيانات الإجبارية: الاسم، اسم الأب، البريد الإلكتروني، رقم الجوال، وكلمة مرور لا تقل عن ٦ أحرف.",
        nextUrl,
        values: fields,
      });
    }

    const exists = await getSiteUserByEmail(fields.email);
    if (exists) {
      await removeUploadedFilesFromRequest(req.files);
      return renderUserAuth(res, {
        mode: "register",
        error: "هذا البريد مسجل بالفعل. جرّب تسجيل الدخول بدل إنشاء حساب جديد.",
        nextUrl,
        values: fields,
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const approvalStatus = newUserApprovalStatus("email");
    const result = await run(
      `INSERT INTO site_users
       (full_name, father_name, mother_name, children_count, birth_date, origin_place, current_residence,
        phone, phone_alt, email, avatar_url, work, qualification, spouse_family, spouse_name, country, city,
        facebook_url, instagram_url, x_url, linkedin_url, cover_url, chat_privacy, profile_visibility, show_phone, show_email, show_birth_date, show_social_links, invite_code_used, approval_status,
        password_hash, provider, is_active, login_count, last_login_at, last_seen_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'email', 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [
        fields.full_name, fields.father_name, fields.mother_name, fields.children_count, fields.birth_date,
        fields.origin_place, fields.current_residence, fields.phone, fields.phone_alt, fields.email, avatarUrl,
        fields.work, fields.qualification, fields.spouse_family, fields.spouse_name, fields.country, fields.city,
        fields.facebook_url, fields.instagram_url, fields.x_url, fields.linkedin_url, coverUrl, fields.chat_privacy,
        fields.profile_visibility, 1, 1, 0, 1, inviteCheck.code || "", approvalStatus, passwordHash,
      ]
    );

    const user = await getSiteUserById(result.lastID);
    await consumeInviteCode(inviteCheck.code);
    await signInSiteUser(req, user);
    await logSiteUserActivity(req, "إنشاء حساب", { email: fields.email });
    return res.redirect((user.approval_status || "approved") === "approved" ? "/account" : "/account-pending");
  } catch (e) {
    await removeUploadedFilesFromRequest(req.files);
    console.error(e);
    return renderUserAuth(res, { mode: "register", error: "حدث خطأ أثناء إنشاء الحساب. تأكد أن البريد غير مستخدم.", values: req.body || {} });
  }
});

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const nextUrl = safeRedirectUrl(req.body.next || "/");
    const user = await getSiteUserByEmail(email);

    if (!user || Number(user.is_active) === 0 || !user.password_hash) {
      return renderUserAuth(res, { mode: "login", error: "بيانات الدخول غير صحيحة أو الحساب غير نشط.", nextUrl, values: { email } });
    }
    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      return renderUserAuth(res, { mode: "login", error: "تم قفل الدخول مؤقتًا بسبب محاولات خاطئة كثيرة. جرّب لاحقًا.", nextUrl, values: { email } });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      const failed = Number(user.failed_login_count || 0) + 1;
      const lockedUntil = failed >= 5 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null;
      await run(`UPDATE site_users SET failed_login_count=?, locked_until=? WHERE id=?`, [failed, lockedUntil, user.id]).catch(() => {});
      return renderUserAuth(res, { mode: "login", error: failed >= 5 ? "محاولات كثيرة خاطئة. تم قفل الدخول ١٥ دقيقة." : "بيانات الدخول غير صحيحة.", nextUrl, values: { email } });
    }

    await run(
      `UPDATE site_users
       SET login_count = COALESCE(login_count, 0) + 1, failed_login_count=0, locked_until=NULL, last_login_at = CURRENT_TIMESTAMP, last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [user.id]
    );
    const fresh = await getSiteUserById(user.id);
    await signInSiteUser(req, fresh);
    await logSiteUserActivity(req, "تسجيل دخول", { method: "email" });
    if ((fresh.approval_status || "approved") !== "approved") return res.redirect("/account-pending");
    return res.redirect(nextUrl);
  } catch (e) {
    console.error(e);
    return renderUserAuth(res, { mode: "login", error: "حدث خطأ أثناء تسجيل الدخول." });
  }
});

app.get("/logout", async (req, res) => {
  await logSiteUserActivity(req, "تسجيل خروج", {});
  clearSiteUserSession(req);
  req.session.save(() => res.redirect("/login?success=" + encodeURIComponent("تم تسجيل الخروج بنجاح")));
});

app.post("/logout", async (req, res) => {
  await logSiteUserActivity(req, "تسجيل خروج", {});
  clearSiteUserSession(req);
  req.session.save(() => res.redirect("/login?success=" + encodeURIComponent("تم تسجيل الخروج بنجاح")));
});

app.get("/auth/google", (req, res, next) => {
  if (!oauthStatus().google) return res.redirect("/login?error=" + encodeURIComponent("تسجيل الدخول عبر Google يحتاج ضبط GOOGLE_CLIENT_ID و GOOGLE_CLIENT_SECRET، مع ضبط PUBLIC_BASE_URL أو GOOGLE_CALLBACK_URL كامل."));
  req.session.oauthNext = safeRedirectUrl(req.query.next || req.headers.referer || "/");
  return passport.authenticate("google", { scope: ["profile", "email"], prompt: "select_account" })(req, res, next);
});

app.get("/auth/google/callback", (req, res, next) => {
  if (!oauthStatus().google) return res.redirect("/login?error=" + encodeURIComponent("Google OAuth غير مفعل"));
  passport.authenticate("google", async (err, user, info) => {
    if (err || !user) {
      return res.redirect("/login?error=" + encodeURIComponent(oauthLoginError("google", err, info)));
    }
    await signInSiteUser(req, user);
    await logSiteUserActivity(req, "تسجيل دخول", { method: "google" });
    const requestedNext = safeRedirectUrl(req.session.oauthNext || "/");
    const nextUrl = (user.approval_status || "approved") !== "approved" ? "/account-pending" : (isSiteUserProfileComplete(user) ? requestedNext : "/account?complete=1");
    delete req.session.oauthNext;
    return res.redirect(nextUrl);
  })(req, res, next);
});


/* =========================
   Site User Account + Family Members
   ========================= */

app.get("/account", async (req, res) => {
  try {
    const user = await getSiteUserById(req.session.siteUser.id);
    if (!user) return res.redirect("/login");
    const treePerson = await findTreePersonForSiteUser(user);
    const honorItem = await findHonorForUser(user, treePerson);
    const stats = await getSiteUserProfileStats(user.id);
    const latestViews = await all(
      `SELECT v.created_at, u.id AS viewer_id, u.full_name AS viewer_name, u.avatar_url AS viewer_avatar
       FROM site_profile_views v
       LEFT JOIN site_users u ON u.id = v.viewer_user_id
       WHERE v.profile_user_id = ?
       ORDER BY v.id DESC
       LIMIT 12`,
      [user.id]
    ).catch(() => []);
    const pendingLink = await get(`SELECT r.*, p.name AS person_name FROM site_user_tree_link_requests r LEFT JOIN persons p ON p.id=r.requested_person_id WHERE r.user_id=? ORDER BY r.id DESC LIMIT 1`, [user.id]).catch(() => null);
    const message = req.query.complete ? "أكمل البيانات الأساسية حتى يظهر حسابك بشكل صحيح لأعضاء العائلة." : (req.query.success || null);
    res.render("user_account", {
      active: "account",
      siteUser: publicSiteUserSession(user),
      user,
      stats,
      latestViews,
      treePerson,
      honorItem,
      pendingLink,
      profileComplete: isSiteUserProfileComplete(user),
      success: message,
      error: req.query.error || null,
      avatar: getSiteUserAvatar(user),
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل حسابك");
  }
});

app.post(
  "/account",
  profileImageUploadHandler("/account"),
  async (req, res) => {
    try {
      const current = await getSiteUserById(req.session.siteUser.id);
      if (!current) {
        await removeUploadedFilesFromRequest(req.files);
        return res.redirect("/login");
      }

      const profileImageSizeError = validateProfileImageSizes(req.files);
      if (profileImageSizeError) {
        await removeUploadedFilesFromRequest(req.files);
        return res.redirect("/account?error=" + encodeURIComponent(profileImageSizeError));
      }

      const fields = extractSiteUserProfileFields(req.body);

      if (!fields.full_name || !fields.father_name || !isValidEmail(fields.email) || !fields.phone) {
        await removeUploadedFilesFromRequest(req.files);
        return res.redirect("/account?error=" + encodeURIComponent("البيانات الإجبارية: الاسم، اسم الأب، البريد الإلكتروني، ورقم الجوال."));
      }

      const sameEmail = await getSiteUserByEmail(fields.email);
      if (sameEmail && Number(sameEmail.id) !== Number(current.id)) {
        await removeUploadedFilesFromRequest(req.files);
        return res.redirect("/account?error=" + encodeURIComponent("هذا البريد مستخدم في حساب آخر."));
      }

      const avatarFile = req.files?.avatar_file?.[0] || req.files?.avatar_file_alt?.[0] || null;
      const coverFile = req.files?.cover_file?.[0] || null;
      const deleteAvatar = String(req.body.delete_avatar || "0") === "1";
      const deleteCover = String(req.body.delete_cover || "0") === "1";

      const oldAvatarUrl = current.avatar_url || "";
      const oldCoverUrl = current.cover_url || "";

      let avatarUrl = oldAvatarUrl;
      let coverUrl = oldCoverUrl;

      if (deleteAvatar) avatarUrl = "";
      if (deleteCover) coverUrl = "";
      if (avatarFile) avatarUrl = `/uploads/${avatarFile.filename}`;
      if (coverFile) coverUrl = `/uploads/${coverFile.filename}`;

      const avatarPosX = (deleteAvatar && !avatarFile) ? "50.00" : normalizePercent(req.body.avatar_pos_x, current.avatar_pos_x ?? 50);
      const avatarPosY = (deleteAvatar && !avatarFile) ? "50.00" : normalizePercent(req.body.avatar_pos_y, current.avatar_pos_y ?? 50);
      const coverPosX = (deleteCover && !coverFile) ? "50.00" : normalizePercent(req.body.cover_pos_x, current.cover_pos_x ?? 50);
      const coverPosY = (deleteCover && !coverFile) ? "50.00" : normalizePercent(req.body.cover_pos_y, current.cover_pos_y ?? 50);

      await run(
        `UPDATE site_users
         SET full_name=?, father_name=?, mother_name=?, children_count=?, birth_date=?, origin_place=?, current_residence=?,
             phone=?, phone_alt=?, email=?, avatar_url=?, avatar_pos_x=?, avatar_pos_y=?, work=?, qualification=?, spouse_family=?, spouse_name=?, country=?, city=?,
             facebook_url=?, instagram_url=?, x_url=?, linkedin_url=?, cover_url=?, cover_pos_x=?, cover_pos_y=?, chat_privacy=?, profile_visibility=?, show_phone=?, show_email=?, show_birth_date=?, show_social_links=?, matched_person_id=?, updated_at=CURRENT_TIMESTAMP
         WHERE id=?`,
        [
          fields.full_name, fields.father_name, fields.mother_name, fields.children_count, fields.birth_date,
          fields.origin_place, fields.current_residence, fields.phone, fields.phone_alt, fields.email, avatarUrl, avatarPosX, avatarPosY,
          fields.work, fields.qualification, fields.spouse_family, fields.spouse_name, fields.country, fields.city,
          fields.facebook_url, fields.instagram_url, fields.x_url, fields.linkedin_url, coverUrl, coverPosX, coverPosY, fields.chat_privacy,
          fields.profile_visibility, fields.show_phone, fields.show_email, fields.show_birth_date, fields.show_social_links, current.matched_person_id || null, current.id,
        ]
      );

      const filesToRemove = [];
      if ((deleteAvatar || avatarFile) && oldAvatarUrl && oldAvatarUrl !== avatarUrl) filesToRemove.push(oldAvatarUrl);
      if ((deleteCover || coverFile) && oldCoverUrl && oldCoverUrl !== coverUrl) filesToRemove.push(oldCoverUrl);
      await Promise.all(filesToRemove.map(removeUploadedFileByUrl));

      const fresh = await getSiteUserById(current.id);
      req.session.siteUser = publicSiteUserSession(fresh);
      req.session.siteUserCheckedAt = Date.now();
      await logSiteUserActivity(req, "تعديل الحساب الشخصي", {
        updated: true,
        avatarDeleted: deleteAvatar && !avatarFile,
        coverDeleted: deleteCover && !coverFile,
        avatarMoved: avatarPosX !== normalizePercent(current.avatar_pos_x, 50) || avatarPosY !== normalizePercent(current.avatar_pos_y, 50),
        coverMoved: coverPosX !== normalizePercent(current.cover_pos_x, 50) || coverPosY !== normalizePercent(current.cover_pos_y, 50),
      });
      res.redirect("/account?success=" + encodeURIComponent("تم حفظ بيانات الحساب بنجاح"));
    } catch (e) {
      await removeUploadedFilesFromRequest(req.files);
      console.error(e);
      res.redirect("/account?error=" + encodeURIComponent("حدث خطأ أثناء حفظ بيانات الحساب"));
    }
  }
);

app.get("/family-members", async (req, res) => {
  try {
    const q = cleanText(req.query.q || "", 160);
    const viewer = await getSiteUserById(req.session.siteUser.id).catch(() => null);
    const params = [];
    let where = "WHERE COALESCE(is_active, 1)=1 AND COALESCE(approval_status, 'approved')='approved' AND COALESCE(profile_visibility, 'members') <> 'private'";
    if (!viewer?.matched_person_id) where += " AND COALESCE(profile_visibility, 'members') <> 'linked_only'";
    if (q) {
      where += ` AND (full_name LIKE ? OR father_name LIKE ? OR mother_name LIKE ? OR email LIKE ? OR phone LIKE ? OR current_residence LIKE ? OR origin_place LIKE ? OR work LIKE ?)`;
      const like = `%${q}%`;
      params.push(like, like, like, like, like, like, like, like);
    }
    const members = await all(
      `SELECT u.id, u.full_name, u.father_name, u.mother_name, u.email, u.phone, u.avatar_url, u.current_residence, u.origin_place, u.work, u.qualification,
              u.spouse_name, u.spouse_family, u.matched_person_id, u.cover_url, u.created_at, u.last_seen_at,
              (SELECT COUNT(*) FROM site_profile_views v WHERE v.profile_user_id = u.id) AS profile_views
       FROM site_users u
       ${where}
       ORDER BY COALESCE(u.last_seen_at, u.created_at) DESC, u.full_name ASC
       LIMIT 300`,
      params
    );
    res.render("family_members", {
      active: "members",
      siteUser: req.session.siteUser,
      members,
      q,
      total: members.length,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل أعضاء العائلة");
  }
});

app.get("/family-members/:id", async (req, res) => {
  try {
    const user = await get(`SELECT * FROM site_users WHERE id = ? AND COALESCE(is_active,1)=1 AND COALESCE(approval_status, 'approved')='approved'`, [req.params.id]);
    if (!user) return res.status(404).send("الحساب غير موجود");
    const viewer = await getSiteUserById(req.session.siteUser.id).catch(() => null);
    const isMeProfile = Number(req.session?.siteUser?.id) === Number(user.id);
    if (!isMeProfile && user.profile_visibility === "private") return res.status(403).send("هذا العضو أخفى حسابه الشخصي.");
    if (!isMeProfile && user.profile_visibility === "linked_only" && !viewer?.matched_person_id) return res.status(403).send("هذا الحساب يظهر للأعضاء المرتبطين بالشجرة فقط.");
    await logProfileView(req, user.id);
    const stats = await getSiteUserProfileStats(user.id);
    const treePerson = await findTreePersonForSiteUser(user);
    const honorItem = await findHonorForUser(user, treePerson);
    const canMessageResult = Number(req.session?.siteUser?.id) === Number(user.id) ? { ok: false, message: "هذا حسابك" } : await canStartPrivateChat(req.session.siteUser.id, user.id);
    res.render("family_member_profile", {
      active: "members",
      siteUser: req.session.siteUser,
      user,
      stats,
      treePerson,
      honorItem,
      avatar: getSiteUserAvatar(user),
      isMe: isMeProfile,
      canMessageResult,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل بيانات العضو");
  }
});

/* =========================
   Site Chat: public + private messages
   ========================= */

app.get("/chat", async (req, res) => {
  try {
    const userId = Number(req.session.siteUser.id);
    if (await isUserChatBlocked(userId)) return res.status(403).send("تم حظرك من استخدام الشات بواسطة الإدارة");
    const publicThread = await ensurePublicChatThread();
    const threads = await all(
      `SELECT t.id, t.type, t.updated_at,
              peer.id AS peer_id, peer.full_name AS peer_name, peer.avatar_url AS peer_avatar,
              lm.body AS last_body, lm.message_type AS last_type, lm.created_at AS last_created_at,
              COALESCE(unread.total, 0) AS unread_count
       FROM site_chat_threads t
       JOIN site_chat_participants mine ON mine.thread_id = t.id AND mine.user_id = ?
       LEFT JOIN site_chat_participants otherp ON otherp.thread_id = t.id AND otherp.user_id <> ?
       LEFT JOIN site_users peer ON peer.id = otherp.user_id
       LEFT JOIN site_chat_messages lm ON lm.id = (SELECT id FROM site_chat_messages WHERE thread_id=t.id AND COALESCE(is_deleted,0)=0 ORDER BY id DESC LIMIT 1)
       LEFT JOIN (
         SELECT m.thread_id, COUNT(*) AS total
         FROM site_chat_messages m
         JOIN site_chat_participants p ON p.thread_id=m.thread_id AND p.user_id=?
         WHERE COALESCE(m.is_deleted,0)=0 AND m.sender_user_id <> ? AND m.id > COALESCE(p.last_read_message_id,0)
         GROUP BY m.thread_id
       ) unread ON unread.thread_id = t.id
       WHERE t.type='private' AND COALESCE(t.is_active,1)=1
       ORDER BY COALESCE(lm.id, t.id) DESC
       LIMIT 100`,
      [userId, userId, userId, userId]
    ).catch(() => []);
    const members = await all(
      `SELECT id, full_name, father_name, avatar_url, current_residence, last_seen_at
       FROM site_users
       WHERE COALESCE(is_active,1)=1 AND id <> ?
       ORDER BY COALESCE(last_seen_at, created_at) DESC, full_name ASC
       LIMIT 80`,
      [userId]
    ).catch(() => []);
    const unread = await unreadPrivateMessagesCount(userId);
    res.render("chat_inbox", { active: "chat", siteUser: req.session.siteUser, publicThread, threads, members, unread });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل الرسائل");
  }
});

app.get("/chat/public", async (req, res) => {
  try {
    if (await isUserChatBlocked(req.session.siteUser.id)) return res.status(403).send("تم حظرك من استخدام الشات بواسطة الإدارة");
    const thread = await ensurePublicChatThread();
    res.render("chat_room", {
      active: "chat",
      siteUser: req.session.siteUser,
      thread,
      roomTitle: thread.title || "الشات العام للعائلة",
      roomSubtitle: "كل أعضاء الموقع يستطيعون رؤية هذه المحادثة. الإدارة يمكنها حذف الرسائل أو إغلاق الشات العام.",
      mode: "public",
      targetUser: null,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل الشات العام");
  }
});

app.get("/chat/private/:userId", async (req, res) => {
  try {
    const me = Number(req.session.siteUser.id);
    const otherId = Number(req.params.userId || 0);
    if (!otherId || otherId === me) return res.redirect("/chat");
    const target = await get(`SELECT id, full_name, father_name, avatar_url, is_active FROM site_users WHERE id=? AND COALESCE(is_active,1)=1`, [otherId]);
    if (!target) return res.status(404).send("المستخدم غير موجود أو موقوف");
    const allowedPrivate = await canStartPrivateChat(me, otherId);
    if (!allowedPrivate.ok) return res.status(403).send(allowedPrivate.message);
    const thread = await getPrivateThreadBetween(me, otherId);
    res.render("chat_room", {
      active: "chat",
      siteUser: req.session.siteUser,
      thread,
      roomTitle: `محادثة مع ${chatDisplayName(target)}`,
      roomSubtitle: "محادثة خاصة بينك وبين هذا العضو فقط، ويمكن للإدارة مراجعتها عند الحاجة لإدارة الموقع.",
      mode: "private",
      targetUser: target,
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء فتح المحادثة");
  }
});

app.get("/api/chat/threads/:threadId/messages", async (req, res) => {
  try {
    const userId = Number(req.session.siteUser.id);
    const threadId = Number(req.params.threadId || 0);
    const thread = await userCanAccessThread(userId, threadId);
    if (!thread) return res.status(403).json({ ok: false, message: "لا تملك صلاحية مشاهدة هذه المحادثة" });
    const after = Number(req.query.after || 0);
    const refresh = String(req.query.refresh || "") === "1";
    const limit = Math.min(Math.max(Number(req.query.limit || 160), 20), 500);
    let rows = [];
    if (refresh || after <= 0) {
      rows = await all(
        `SELECT * FROM (
           SELECT m.*, u.full_name AS sender_name, u.avatar_url AS sender_avatar
           FROM site_chat_messages m
           LEFT JOIN site_users u ON u.id = m.sender_user_id
           WHERE m.thread_id = ? AND COALESCE(m.is_deleted,0)=0
           ORDER BY m.id DESC
           LIMIT ?
         ) ORDER BY id ASC`,
        [threadId, limit]
      );
    } else {
      rows = await all(
        `SELECT m.*, u.full_name AS sender_name, u.avatar_url AS sender_avatar
         FROM site_chat_messages m
         LEFT JOIN site_users u ON u.id = m.sender_user_id
         WHERE m.thread_id = ? AND m.id > ? AND COALESCE(m.is_deleted,0)=0
         ORDER BY m.id ASC
         LIMIT ?`,
        [threadId, after, limit]
      );
    }
    const lastId = rows.length ? rows[rows.length - 1].id : after;
    if (thread.type === "private") {
      await run(`UPDATE site_chat_participants SET last_read_message_id = MAX(COALESCE(last_read_message_id,0), ?) WHERE thread_id=? AND user_id=?`, [lastId, threadId, userId]).catch(() => {});
    }
    return res.json({ ok: true, messages: await serializeChatMessages(rows, { currentUserId: userId, threadId }), lastId, locked: Number(thread.is_locked) === 1, socket: Boolean(io) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "حدث خطأ أثناء تحميل الرسائل" });
  }
});

app.get("/api/chat/unread-count", async (req, res) => {
  try {
    const userId = Number(req.session?.siteUser?.id || 0);
    if (!userId) return res.status(401).json({ ok: false, unread: 0 });
    const unread = await unreadPrivateMessagesCount(userId);
    return res.json({ ok: true, unread });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, unread: 0 });
  }
});

app.post("/api/chat/threads/:threadId/messages", (req, res, next) => {
  chatUpload.single("chat_file")(req, res, function (err) {
    if (err) return res.status(400).json({ ok: false, message: err.message || "تعذر رفع الملف" });
    return next();
  });
}, async (req, res) => {
  try {
    const userId = Number(req.session.siteUser.id);
    const threadId = Number(req.params.threadId || 0);
    if (await isUserChatBlocked(userId)) return res.status(403).json({ ok: false, message: "تم حظرك من استخدام الشات بواسطة الإدارة" });
    const thread = await userCanAccessThread(userId, threadId);
    if (!thread) return res.status(403).json({ ok: false, message: "لا تملك صلاحية إرسال رسالة هنا" });
    if (Number(thread.is_locked) === 1) return res.status(403).json({ ok: false, message: "الشات مغلق مؤقتًا بواسطة الإدارة" });
    if (thread.type === "private") {
      const other = await get(`SELECT user_id FROM site_chat_participants WHERE thread_id=? AND user_id<>? LIMIT 1`, [threadId, userId]).catch(() => null);
      if (other?.user_id) {
        const allowedPrivate = await canStartPrivateChat(userId, other.user_id);
        if (!allowedPrivate.ok) return res.status(403).json({ ok: false, message: allowedPrivate.message });
      }
    }

    const body = await filterChatBody(req.body.body || "");
    const file = req.file || null;
    if (!body && !file) return res.status(400).json({ ok: false, message: "اكتب رسالة أو أرفق صورة/تسجيلًا صوتيًا" });

    const messageType = file ? chatAttachmentType(file) : "text";
    const attachmentUrl = file ? `/uploads/chat/${file.filename}` : "";
    const result = await run(
      `INSERT INTO site_chat_messages
       (thread_id, sender_user_id, body, message_type, attachment_url, attachment_name, attachment_mime, attachment_size, ip_address, user_agent, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [threadId, userId, body, messageType, attachmentUrl, file?.originalname || "", file?.mimetype || "", file?.size || 0, getClientIp(req), String(req.headers["user-agent"] || "").slice(0, 300)]
    );
    await run(`UPDATE site_chat_threads SET updated_at=CURRENT_TIMESTAMP WHERE id=?`, [threadId]);
    await logSiteUserActivity(req, thread.type === "public" ? "رسالة في الشات العام" : "رسالة خاصة", { threadId, messageId: result.lastID, type: messageType });
    if (thread.type === "private") {
      const recipient = await get(`SELECT user_id FROM site_chat_participants WHERE thread_id=? AND user_id<>? LIMIT 1`, [threadId, userId]).catch(() => null);
      if (recipient?.user_id) await createNotification(recipient.user_id, "رسالة خاصة جديدة", "لديك رسالة جديدة داخل الموقع.", `/chat/private/${userId}`, "chat");
    }
    const rows = await all(
      `SELECT m.*, u.full_name AS sender_name, u.avatar_url AS sender_avatar
       FROM site_chat_messages m
       LEFT JOIN site_users u ON u.id = m.sender_user_id
       WHERE m.id = ?`,
      [result.lastID]
    );
    const serialized = (await serializeChatMessages(rows, { currentUserId: userId, threadId }))[0];
    emitChatThreadUpdate(threadId, "message", { messageId: result.lastID });
    return res.json({ ok: true, message: serialized });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "حدث خطأ أثناء إرسال الرسالة" });
  }
});

app.post("/api/chat/messages/:messageId/edit", async (req, res) => {
  try {
    const userId = Number(req.session.siteUser.id);
    const messageId = Number(req.params.messageId || 0);
    const body = await filterChatBody(req.body.body || "");
    if (!messageId) return res.status(400).json({ ok: false, message: "رسالة غير صحيحة" });

    const message = await get(
      `SELECT m.*, t.type AS thread_type, t.is_locked, t.is_active
       FROM site_chat_messages m
       JOIN site_chat_threads t ON t.id=m.thread_id
       WHERE m.id=? AND COALESCE(m.is_deleted,0)=0`,
      [messageId]
    );
    if (!message) return res.status(404).json({ ok: false, message: "الرسالة غير موجودة" });
    if (Number(message.sender_user_id) !== userId) return res.status(403).json({ ok: false, message: "يمكنك تعديل رسائلك فقط" });
    const thread = await userCanAccessThread(userId, message.thread_id);
    if (!thread) return res.status(403).json({ ok: false, message: "لا تملك صلاحية تعديل هذه الرسالة" });
    if (Number(message.is_locked) === 1) return res.status(403).json({ ok: false, message: "لا يمكن التعديل لأن المحادثة مغلقة مؤقتًا" });
    if (!body && !message.attachment_url) return res.status(400).json({ ok: false, message: "لا يمكن حفظ رسالة فارغة" });

    await run(
      `UPDATE site_chat_messages
       SET body=?, edited_at=CURRENT_TIMESTAMP, edited_by_user_id=?, updated_at=CURRENT_TIMESTAMP
       WHERE id=?`,
      [body, userId, messageId]
    );
    await run(`UPDATE site_chat_threads SET updated_at=CURRENT_TIMESTAMP WHERE id=?`, [message.thread_id]).catch(() => {});
    await logSiteUserActivity(req, "تعديل رسالة", { threadId: message.thread_id, messageId });
    const rows = await all(
      `SELECT m.*, u.full_name AS sender_name, u.avatar_url AS sender_avatar
       FROM site_chat_messages m
       LEFT JOIN site_users u ON u.id = m.sender_user_id
       WHERE m.id = ? AND COALESCE(m.is_deleted,0)=0`,
      [messageId]
    );
    const serialized = (await serializeChatMessages(rows, { currentUserId: userId, threadId: message.thread_id }))[0];
    emitChatThreadUpdate(message.thread_id, "edit", { messageId });
    return res.json({ ok: true, message: serialized });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "حدث خطأ أثناء تعديل الرسالة" });
  }
});


app.post("/api/chat/messages/:messageId/report", async (req, res) => {
  try {
    const userId = Number(req.session.siteUser.id);
    const messageId = Number(req.params.messageId || 0);
    const reason = cleanText(req.body.reason || "", 500) || "بلاغ من المستخدم";
    const message = await get(
      `SELECT m.*, t.id AS thread_id
       FROM site_chat_messages m
       JOIN site_chat_threads t ON t.id=m.thread_id
       WHERE m.id=? AND COALESCE(m.is_deleted,0)=0`,
      [messageId]
    );
    if (!message) return res.status(404).json({ ok: false, message: "الرسالة غير موجودة" });
    const thread = await userCanAccessThread(userId, message.thread_id);
    if (!thread) return res.status(403).json({ ok: false, message: "لا تملك صلاحية الإبلاغ عن هذه الرسالة" });
    if (Number(message.sender_user_id) === userId) return res.status(400).json({ ok: false, message: "لا يمكنك الإبلاغ عن رسالتك" });
    await run(
      `INSERT INTO site_chat_message_reports (message_id, reporter_user_id, reason, status, created_at)
       VALUES (?, ?, ?, 'pending', CURRENT_TIMESTAMP)`,
      [messageId, userId, reason]
    );
    await logSiteUserActivity(req, "بلاغ عن رسالة", { messageId, threadId: message.thread_id });
    return res.json({ ok: true, message: "تم إرسال البلاغ للإدارة" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "حدث خطأ أثناء إرسال البلاغ" });
  }
});

/* =========================
   Public Routes
   ========================= */

app.get("/", (req, res) => {
  res.render("home", { active: "tree", siteUser: req.session.siteUser });
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


/* =========================
   Smart assistant interaction layer
   Fixes: word math, jokes, search commands, and short session memory
   ========================= */
function smartArabicNumber(value) {
  const formatted = Number(value).toLocaleString("en-US", { maximumFractionDigits: 6 });
  return formatted.replace(/\d/g, (d) => "٠١٢٣٤٥٦٧٨٩"[Number(d)]);
}

function normalizeSmartQuestion(value) {
  return normalizeDigitsToLatin(String(value || ""))
    .toLowerCase()
    .replace(/[أإآٱ]/g, "ا")
    .replace(/ى/g, "ي")
    .replace(/ة/g, "ه")
    .replace(/[ًٌٍَُِّْـ]/g, "")
    .replace(/[؟?،,؛;:]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function smartParseNumberPhrase(input) {
  let text = normalizeSmartQuestion(input)
    .replace(/جنيه|ريال|دولار|egp|sar|usd/g, " ")
    .replace(/,/g, "")
    .trim();

  if (!text) return null;
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return Number(text);

  const directDigitWithScale = text.match(/^(-?\d+(?:\.\d+)?)\s*(الف|الاف|الفا|k|مليون|ملايين|million|m)$/i);
  if (directDigitWithScale) {
    const n = Number(directDigitWithScale[1]);
    const scale = directDigitWithScale[2];
    if (/الف|الاف|الفا|k/.test(scale)) return n * 1000;
    if (/مليون|ملايين|million|m/.test(scale)) return n * 1000000;
  }

  const units = {
    "صفر":0,"زيرو":0,"zero":0,
    "واحد":1,"واحده":1,"واحدة":1,"احد":1,"one":1,
    "اثنين":2,"اثنان":2,"اتنين":2,"تنين":2,"two":2,
    "ثلاثه":3,"ثلاثة":3,"تلاته":3,"تلاتة":3,"ثلاث":3,"three":3,
    "اربعه":4,"اربعة":4,"اربع":4,"four":4,
    "خمسه":5,"خمسة":5,"خمس":5,"five":5,
    "سته":6,"ستة":6,"ست":6,"six":6,
    "سبعه":7,"سبعة":7,"سبع":7,"seven":7,
    "ثمانيه":8,"ثمانية":8,"ثمان":8,"تمنيه":8,"تمنية":8,"eight":8,
    "تسعه":9,"تسعة":9,"تسع":9,"nine":9,
    "عشره":10,"عشرة":10,"عشر":10,"ten":10,
    "احداشر":11,"احد عشر":11,"حداشر":11,"eleven":11,
    "اتناشر":12,"اثنا عشر":12,"اثني عشر":12,"twelve":12,
    "تلتاشر":13,"ثلاثه عشر":13,"ثلاثة عشر":13,"thirteen":13,
    "اربعتاشر":14,"اربعه عشر":14,"اربعة عشر":14,"fourteen":14,
    "خمستاشر":15,"خمسه عشر":15,"خمسة عشر":15,"fifteen":15,
    "ستاشر":16,"سته عشر":16,"ستة عشر":16,"sixteen":16,
    "سبعتاشر":17,"سبعه عشر":17,"سبعة عشر":17,"seventeen":17,
    "تمنتاشر":18,"ثمانيه عشر":18,"ثمانية عشر":18,"eighteen":18,
    "تسعتاشر":19,"تسعه عشر":19,"تسعة عشر":19,"nineteen":19
  };
  const tens = {
    "عشرين":20,"عشرون":20,"twenty":20,
    "تلاتين":30,"ثلاثين":30,"thirty":30,
    "اربعين":40,"forty":40,
    "خمسين":50,"fifty":50,
    "ستين":60,"sixty":60,
    "سبعين":70,"seventy":70,
    "تمانين":80,"ثمانين":80,"eighty":80,
    "تسعين":90,"ninety":90
  };
  const hundreds = {
    "ميه":100,"مية":100,"مائه":100,"مائة":100,"hundred":100,
    "ميتين":200,"مئتين":200,"مائتين":200,"two hundred":200,
    "تلتميه":300,"ثلاثميه":300,"ثلاثمائة":300,"ثلاثمائه":300,
    "ربعمية":400,"اربعمائة":400,"اربعمائه":400,
    "خمسمية":500,"خمسمائه":500,"خمسمائة":500,
    "ستمية":600,"ستمائه":600,"ستمائة":600,
    "سبعمية":700,"سبعمائه":700,"سبعمائة":700,
    "تمنمية":800,"ثمانمائه":800,"ثمانمائة":800,
    "تسعمية":900,"تسعمائه":900,"تسعمائة":900
  };

  // Direct multi-word phrases first.
  const joined = text.replace(/\s+و\s+/g, " ").trim();
  for (const [k, v] of Object.entries({...units, ...tens, ...hundreds})) {
    if (joined === k) return v;
  }

  let total = 0;
  let current = 0;
  const tokens = text.replace(/\bو(?=\S)/g, "و ").split(/\s+|-/).filter(Boolean).map(t => t.replace(/^و/, "")).filter(Boolean);

  for (const token of tokens) {
    if (/^-?\d+(?:\.\d+)?$/.test(token)) {
      current += Number(token);
      continue;
    }
    if (units[token] != null) { current += units[token]; continue; }
    if (tens[token] != null) { current += tens[token]; continue; }
    if (hundreds[token] != null) { current += hundreds[token]; continue; }

    if (["مائه","مائة","ميه","مية","hundred"].includes(token)) {
      current = (current || 1) * 100;
      continue;
    }
    if (["الف","الاف","الفا","thousand","k"].includes(token)) {
      total += (current || 1) * 1000;
      current = 0;
      continue;
    }
    if (["مليون","ملايين","million","m"].includes(token)) {
      total += (current || 1) * 1000000;
      current = 0;
      continue;
    }
  }

  const result = total + current;
  return result || null;
}

function answerSmartMathQuestion(question) {
  const q = normalizeSmartQuestion(question)
    .replace(/احسبلي|احسب|كام|كم|يساوي|يساوى|بكام|ناتج|what is|calculate|please/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const ops = [
    { label: "-", words: ["ناقص", "اطرح", "طرح", "minus", "-"] },
    { label: "+", words: ["زائد", "جمع", "اجمع", "plus", "+"] },
    { label: "×", words: ["في", "ضرب", "اضرب", "times", "x", "*", "×"] },
    { label: "÷", words: ["علي", "على", "قسمه", "قسمة", "اقسم", "divide", "/", "÷"] },
  ];

  for (const op of ops) {
    for (const word of op.words) {
      const safe = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(`(.+?)\\s*(?:${safe})\\s*(.+)`, "i");
      const m = q.match(re);
      if (!m) continue;
      const a = smartParseNumberPhrase(m[1]);
      const b = smartParseNumberPhrase(m[2]);
      if (!Number.isFinite(a) || !Number.isFinite(b)) continue;
      if (op.label === "÷" && b === 0) return { answer: "لا يمكن القسمة على صفر يا كبير 😄" };
      let result = 0;
      if (op.label === "+") result = a + b;
      if (op.label === "-") result = a - b;
      if (op.label === "×") result = a * b;
      if (op.label === "÷") result = Number((a / b).toFixed(6));
      return { answer: `${smartArabicNumber(a)} ${op.label} ${smartArabicNumber(b)} = ${smartArabicNumber(result)}.` };
    }
  }
  return null;
}

function answerSmartHumorQuestion(question) {
  const nq = normalizeSmartQuestion(question);
  if (["نكته", "نكتة", "هزر", "ضحكني", "joke", "funny"].some((w) => nq.includes(normalizeSmartQuestion(w)))) {
    const jokes = [
      "مرة واحد دخل شجرة العائلة… لقى نفسه ابن عم نص الموقع 😄",
      "مرة واحد كتب الاسم ثنائي وزعل إني ملقتوش… قولتله يا باشا الشجرة بتحب الاسم الثلاثي 😄",
      "مرة مساعد ذكي اتسأل: عندك كام ولد؟ قالهم أنا عندي bugs بس وبصلحها 😄",
      "النسب زي الواي فاي… لازم تبقى قريب عشان الإشارة تبان 😄"
    ];
    return { answer: jokes[Math.floor(Math.random() * jokes.length)] + "\nتحب أبحث لك عن شخص في الشجرة؟" };
  }
  if (["غبي", "مش فاهم", "انت نايم", "stupid"].some((w) => nq.includes(normalizeSmartQuestion(w)))) {
    return { answer: "حقك عليّا 😄 اسألني بصيغة أوضح أو اكتب الاسم ثلاثي، وأنا هحاول أظبطها. مثال: ابحث عن وسيم إبراهيم حسن." };
  }
  return null;
}

function extractSmartPersonSearchName(question) {
  let q = cleanText(String(question || ""), 300);
  const patterns = [
    /^(?:دورلي\s+على|دورلي\s+علي|دور\s+لي\s+على|دور\s+لي\s+علي|ابحث\s+عن|ابحث\s+على|ابحث\s+علي|ابحثلي\s+عن|ابحثلي\s+على|فتش\s+عن|هات\s+لي|هاتلي|اعرض|وريني|show\s+me|find|search\s+for)\s+(.+)$/i,
    /^(?:فين|وين|اين|أين)\s+(.+)$/i,
  ];
  for (const re of patterns) {
    const m = q.match(re);
    if (m && m[1]) return stripAssistantNameNoise(m[1]);
  }
  return "";
}

function isFollowupChildrenQuestion(question) {
  const nq = normalizeSmartQuestion(question);
  return ["عنده كام ولد", "عندها كام ولد", "عنده كم ولد", "عندها كم ولد", "كام ولد", "كم ولد", "عنده كام بنت", "عندها كام بنت", "كم بنت", "كام بنت", "عنده كام عيل", "عنده كم عيال", "اولاده", "أولاده", "ابناؤه", "ابناءه", "بناته"].some((w) => nq.includes(normalizeSmartQuestion(w)));
}

function wantedChildType(question) {
  const nq = normalizeSmartQuestion(question);
  if (nq.includes("بنت") || nq.includes("بنات")) return "daughters";
  if (nq.includes("ولد") || nq.includes("اولاد") || nq.includes("ابناء") || nq.includes("عيال")) return "sons";
  return "all";
}

async function answerChildrenForPersonObject(person, rows) {
  const children = rows.filter((x)=>Number(x.father_id)===Number(person.id)||Number(x.mother_id)===Number(person.id));
  const sons = children.filter((c)=>genderIsMale(c));
  const daughters = children.filter((c)=>genderIsFemale(c));
  const unknown = children.length - sons.length - daughters.length;
  const lines = [`${person.name} لديه/لديها ${smartArabicNumber(children.length)} من الأبناء المسجلين في الشجرة.`];
  lines.push(`الأولاد: ${smartArabicNumber(sons.length)}${sons.length ? ` — ${sons.map(c=>c.name).join("، ")}` : ""}.`);
  lines.push(`البنات: ${smartArabicNumber(daughters.length)}${daughters.length ? ` — ${daughters.map(c=>c.name).join("، ")}` : ""}.`);
  if (unknown > 0) lines.push(`غير محدد النوع: ${smartArabicNumber(unknown)}.`);
  return { answer: lines.join("\n"), actions: [{ label: "عرض موقعه في الشجرة", url: `/?focus=${person.id}` }], memory: makePersonConversationMemory(person, rows) };
}

async function answerChildrenFromContext(question, context = {}) {
  if (!isFollowupChildrenQuestion(question) || !context.lastPersonId) return null;
  const { rows, byId } = await getPersonsForRelationship();
  const person = byId.get(Number(context.lastPersonId));
  if (!person) return null;
  const allAnswer = await answerChildrenForPersonObject(person, rows);
  const type = wantedChildType(question);
  if (type === "all") return allAnswer;
  const children = rows.filter((x)=>Number(x.father_id)===Number(person.id)||Number(x.mother_id)===Number(person.id));
  const list = type === "sons" ? children.filter((c)=>genderIsMale(c)) : children.filter((c)=>genderIsFemale(c));
  const label = type === "sons" ? "الأولاد" : "البنات";
  return {
    answer: `${label} المسجلون/المسجلات لـ ${person.name}: ${smartArabicNumber(list.length)}${list.length ? `\nالأسماء: ${list.map(c=>c.name).join("، ")}` : "."}`,
    actions: [{ label: "عرض موقعه في الشجرة", url: `/?focus=${person.id}` }],
    memory: makePersonConversationMemory(person, rows)
  };
}

async function answerSiteAssistant(question, context = {}, req = null) {
  const q = cleanText(question, 600);
  const nq = normalizeArabicForMatch(q);
  if (!q) return { answer: "اكتب سؤالك أولًا عن الموقع أو العائلة." };

  if (req) {
    const entertainmentAnswer = answerFromEntertainment(q, req);
    if (entertainmentAnswer) return entertainmentAnswer;
  }

  const smartMath = answerSmartMathQuestion(q) || answerSimpleMathQuestion(q);
  if (smartMath) return smartMath;

  const smartHumor = answerSmartHumorQuestion(q);
  if (smartHumor) return smartHumor;

  const contextChildren = await answerChildrenFromContext(q, context);
  if (contextChildren) return contextChildren;

  const contextPerson = await answerPersonFromConversationContext(q, context);
  if (contextPerson) return contextPerson;

  const greetingAnswer = answerGreetingQuestion(q);
  if (greetingAnswer) return greetingAnswer;

  const dateTimeAnswer = answerDateTimeQuestion(q);
  if (dateTimeAnswer) return dateTimeAnswer;

  if (isFamilyHistoryQuestion(q)) return await getFamilyHistoryAssistantAnswer();

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
      actions: [{ label: "عرض الحساب في صفحة صلة القرابة", url: `/kinship?person_a=${encodeURIComponent(kinshipNames.a)}&person_b=${encodeURIComponent(kinshipNames.b)}` }]
    };
  }

  const explicitSearchName = extractSmartPersonSearchName(q);
  if (explicitSearchName) {
    const { rows, byId } = await getPersonsForRelationship();
    const match = matchPersonByFlexibleName(explicitSearchName, rows, byId);
    if (match.status === "matched") {
      const result = await buildPersonAssistantAnswer(match.matches[0], rows, byId);
      result.memory = makePersonConversationMemory(match.matches[0], rows);
      return result;
    }
    if (match.status === "multiple") {
      return {
        answer: `وجدت أكثر من نتيجة محتملة. اكتب الاسم رباعي أو اختر من النتائج:\n${match.matches.map((x, i)=>`${i+1}- ${x.name} (${x.lineage_label})`).join("\n")}`,
        actions: match.matches.flatMap((x)=>[
          { label: `موقع ${x.name} في الشجرة`, url: `/?focus=${x.id}` },
          { label: `سيرة ${x.name}`, url: `/honor?personId=${encodeURIComponent(x.id)}` }
        ]).slice(0, 10)
      };
    }
    return { answer: `دورت على "${explicitSearchName}" لكن لم أجد نتيجة مطابقة داخل الشجرة. جرّب تكتب الاسم ثلاثي/رباعي أو راجع الهمزات وطريقة الكتابة.` };
  }

  if (isAgeQuestion(q)) {
    const ageAnswer = await answerPersonAgeQuestion(q);
    if (ageAnswer) return ageAnswer;
  }

  if (isChildrenCountQuestion(q)) {
    const childrenAnswer = await answerChildrenCountQuestion(q);
    if (childrenAnswer) {
      // Try to attach memory from the name inside the answer by resolving again when possible.
      return childrenAnswer;
    }
    return { answer: context.lastPersonName ? `تقصد ${context.lastPersonName}؟ اكتب مثلًا: عنده كام ولد أو عنده كام بنت.` : "اكتب اسم الشخص ثلاثي أو رباعي بعد السؤال. مثال: وسيم إبراهيم حسن عنده كام ولد وكم بنت؟" };
  }

  const faqAnswer = answerWebsiteFAQ(q);
  if (faqAnswer) return faqAnswer;

  const dictionaryAnswer = await answerFromAssistantKnowledge(q);
  if (dictionaryAnswer) return dictionaryAnswer;

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
  if (match.status === "matched") {
    const result = await buildPersonAssistantAnswer(match.matches[0], rows, byId);
    result.memory = { lastPersonId: match.matches[0].id, lastPersonName: match.matches[0].name };
    return result;
  }
  if (match.status === "multiple") {
    return {
      answer: `وجدت أكثر من نتيجة محتملة. اختر الشخص المقصود أو اكتب الاسم رباعي لتحديده بدقة:\n${match.matches.map((x, i)=>`${i+1}- ${x.name} (${x.lineage_label})`).join("\n")}`,
      actions: match.matches.flatMap((x)=>[
        { label: `موقع ${x.name} في الشجرة`, url: `/?focus=${x.id}` },
        { label: `سيرة ${x.name}`, url: `/honor?personId=${encodeURIComponent(x.id)}` }
      ]).slice(0, 10)
    };
  }
  if (shouldSearchPerson) {
    return { answer: `لم أجد شخصًا مطابقًا لاسم "${personQuery || q}" داخل الشجرة. برجاء كتابة الاسم ثلاثي أو رباعي، أو التأكد من طريقة كتابة الاسم.` };
  }

  return { answer: "مش متأكد إني فهمت قصدك 😄 جرّب تسألني بصيغة أوضح، أو اكتب: ابحث عن اسم شخص، افتح الأخبار، احسب ١٠٠ ناقص ٥٠، أو قولي نكتة." };
}

app.post("/api/site-assistant", async (req, res) => {
  try {
    const question = req.body?.question || "";
    req.session.assistantContext = req.session.assistantContext || {};

    const siteAnswer = await answerSiteAssistant(question, req.session.assistantContext, req);

    if (siteAnswer?.memory) {
      req.session.assistantContext = {
        ...req.session.assistantContext,
        ...siteAnswer.memory,
        updatedAt: Date.now()
      };
      delete siteAnswer.memory;
    }

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

app.post("/news/:id/like", async (req, res) => {
  try {
    const postId = Number(req.params.id);
    if (!postId) return res.status(400).json({ ok: false, error: "خبر غير صالح" });

    // تأكد أن الخبر موجود ومفعل قبل تسجيل الإعجاب
    const post = await get(
      `SELECT id
       FROM news_posts
       WHERE id = ?
         AND COALESCE(is_active, 1) = 1
       LIMIT 1`,
      [postId]
    );

    if (!post) {
      return res.status(404).json({ ok: false, error: "الخبر غير موجود" });
    }

    const ip = getClientIp(req);

    // بدون قيود نهائيًا:
    // كل ضغطة على زر الإعجاب تضيف إعجابًا جديدًا حتى من نفس المستخدم أو نفس الـ IP.
    await run(
      `INSERT INTO news_likes (post_id, ip_address, created_at)
       VALUES (?, ?, datetime('now'))`,
      [postId, ip]
    );

    const count = await get(
      `SELECT COUNT(*) AS c
       FROM news_likes
       WHERE post_id = ?`,
      [postId]
    );

    return res.json({
      ok: true,
      count: Number(count?.c || 0),
      added: true,
      alreadyLiked: false
    });
  } catch (e) {
    console.error("news like error:", e);
    return res.status(500).json({ ok: false, error: "like_failed" });
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
   Branch Tree Export
   ========================= */

app.get("/tree-export", async (req, res) => {
  res.render("tree_export", {
    active: "tree-export",
    siteUser: req.session.siteUser,
    initialName: cleanText(req.query.name || "", 180),
    initialPersonId: Number(req.query.person_id || 0) || null,
  });
});

app.get("/api/tree/export/search", async (req, res) => {
  try {
    const q = cleanText(req.query.q || req.query.name || "", 180);
    if (!q || namePartsForMatch(q).length < 2) {
      return res.status(400).json({ ok: false, error: "اكتب اسمًا ثنائيًا على الأقل، والأفضل الاسم الثلاثي أو الرباعي." });
    }

    const result = await findExportPersonCandidates(q);
    if (!result.candidates.length) {
      return res.json({ ok: true, status: "not_found", candidates: [], message: "لم يتم العثور على شخص مطابق. جرّب الاسم الثلاثي أو الرباعي." });
    }

    return res.json({ ok: true, ...result });
  } catch (e) {
    console.error("tree export search error:", e);
    res.status(500).json({ ok: false, error: "حدث خطأ أثناء البحث عن الاسم." });
  }
});

app.get("/api/tree/export/branch/:personId", async (req, res) => {
  try {
    const personId = Number(req.params.personId || 0);
    if (!personId) return res.status(400).json({ ok: false, error: "رقم الشخص غير صحيح." });

    const includePhotos = String(req.query.photos ?? "1") !== "0";
    const maxDepth = safeExportDepth(req.query.generations || 99);
    const rows = await all(`
      SELECT id, name, father_id, mother_id, gender, birth_date, photo_url, job
      FROM persons
      ORDER BY id ASC
    `);
    const byId = new Map(rows.map((r) => [Number(r.id), { ...r, id: Number(r.id) }]));
    const root = byId.get(personId);
    if (!root) return res.status(404).json({ ok: false, error: "الشخص غير موجود في الشجرة." });

    const branch = buildLineageBranchExportTree(root, rows, { maxDepth, includePhotos });
    return res.json({
      ok: true,
      mode: "lineage_branch",
      root: publicPersonForExport(root),
      tree: branch.tree,
      personsCount: branch.count,
      generationsCount: branch.generations,
      ancestorsCount: branch.ancestorsCount || 0,
      options: { includePhotos, maxDepth: maxDepth >= 99 ? "all" : maxDepth, includeAncestors: true },
      title: `مخطط ${root.name} والأصول والذرية`,
      createdAt: new Date().toISOString(),
    });
  } catch (e) {
    console.error("tree export branch error:", e);
    res.status(500).json({ ok: false, error: "حدث خطأ أثناء تجهيز الفرع." });
  }
});

app.get("/api/tree/export/full", async (req, res) => {
  try {
    const includePhotos = String(req.query.photos ?? "1") !== "0";
    // compact=1 هو الوضع الافتراضي السريع: لا نرسل شجرة متداخلة ضخمة، بل قائمة مسطحة بكل الأشخاص.
    // هذا يقلل حجم الاستجابة وتسريع المعاينة والطباعة عند وجود مئات/آلاف الأسماء.
    const compact = String(req.query.compact ?? "1") !== "0";
    const rows = await all(`
      SELECT id, name, father_id, mother_id, gender, birth_date, photo_url, job
      FROM persons
      ORDER BY id ASC
    `);

    const full = buildFullTreeExport(rows, { includePhotos });
    return res.json({
      ok: true,
      mode: "full_tree",
      root: { id: null, name: "الشجرة كاملة" },
      tree: compact ? null : full.tree,
      persons: full.persons || [],
      personsCount: full.count,
      generationsCount: full.generations,
      rootsCount: full.rootsCount || 0,
      detachedRootsCount: full.detachedRootsCount || 0,
      includedAllPersons: true,
      compact: compact ? 1 : 0,
      options: { includePhotos, maxDepth: "all", fullTree: true, includeEveryPerson: true, compact },
      title: "المخطط الكامل لكل أسماء شجرة العائلة",
      createdAt: new Date().toISOString(),
    });
  } catch (e) {
    console.error("tree export full error:", e);
    res.status(500).json({ ok: false, error: "حدث خطأ أثناء تجهيز المخطط الكامل." });
  }
});

app.post("/api/tree/export/log", async (req, res) => {
  try {
    const userId = Number(req.session?.siteUser?.id || 0) || null;
    const personId = Number(req.body.person_id || 0) || null;
    const personName = cleanText(req.body.person_name || "", 180);
    const exportTitle = cleanText(req.body.export_title || "", 220);
    const personsCount = Math.min(Math.max(Number(req.body.persons_count || 0), 0), 100000);
    const generationsCount = Math.min(Math.max(Number(req.body.generations_count || 0), 0), 1000);

    await run(
      `INSERT INTO tree_export_logs (user_id, person_id, person_name, export_title, export_options, persons_count, generations_count, ip_address, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [userId, personId, personName, exportTitle, JSON.stringify(req.body.options || {}), personsCount, generationsCount, getClientIp(req), String(req.headers["user-agent"] || "").slice(0, 300)]
    ).catch(() => {});

    await logSiteUserActivity(req, "تصدير فرع من الشجرة", { person_id: personId, person_name: personName, persons_count: personsCount });
    res.json({ ok: true });
  } catch (e) {
    console.error("tree export log error:", e);
    res.status(500).json({ ok: false });
  }
});

app.get("/admin/tree-exports", isAuthed, requireAnyPermission(["users", "backups", "all"]), async (req, res) => {
  try {
    const logs = await all(`
      SELECT l.*, u.full_name AS user_name, u.email AS user_email
      FROM tree_export_logs l
      LEFT JOIN site_users u ON u.id = l.user_id
      ORDER BY l.id DESC
      LIMIT 300
    `).catch(() => []);
    res.render("admin_tree_exports", { admin: req.session.admin, logs, userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل سجل التصدير");
  }
});

/* =========================
   API
   ========================= */

app.get("/api/tree", async (req, res) => {
  try {
    let rows = await all(`
      SELECT
        id, name, father_id, mother_id, birth_date, birth_place,
        death_date, death_place, is_deceased, gender, job, education_level, lineage,
        photo_url, notes, short_bio
      FROM persons
      ORDER BY id ASC
    `);

    const linkedUsers = await all(`
      SELECT id, full_name, avatar_url, verification_status, matched_person_id
      FROM site_users
      WHERE matched_person_id IS NOT NULL
        AND COALESCE(is_active,1)=1
        AND COALESCE(approval_status,'approved')='approved'
        AND COALESCE(profile_visibility,'members') <> 'private'
      ORDER BY id ASC
    `).catch(() => []);
    const profileByPersonId = new Map();
    for (const u of linkedUsers) {
      const pid = Number(u.matched_person_id || 0);
      if (!pid || profileByPersonId.has(pid)) continue;
      profileByPersonId.set(pid, {
        id: u.id,
        full_name: u.full_name || '',
        avatar_url: u.avatar_url || '',
        verification_status: u.verification_status || 'verified'
      });
    }
    rows = rows.map((row) => ({ ...row, site_profile: profileByPersonId.get(Number(row.id)) || null }));

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
    const linkedUser = await get(
      `SELECT id, full_name, avatar_url, verification_status
       FROM site_users
       WHERE CAST(matched_person_id AS INTEGER) = ?
         AND COALESCE(is_active,1)=1
         AND COALESCE(approval_status,'approved')='approved'
         AND COALESCE(profile_visibility,'members') <> 'private'
       ORDER BY id ASC LIMIT 1`,
      [Number(row.id)]
    ).catch(() => null);

    res.json({
      ...row,
      site_profile: linkedUser ? { id: linkedUser.id, full_name: linkedUser.full_name || '', avatar_url: linkedUser.avatar_url || '', verification_status: linkedUser.verification_status || '' } : null,
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
  req.session.destroy(() => res.redirect("/admin/login"));
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
      userCan: (perm) => userCan(req.session.admin, perm),
      permissionGroups: PERMISSION_GROUPS,
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
    res.render("admin_timeline_edit", { admin: req.session.admin, event: row, userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS }); 
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
    res.render("honor_admin", { admin: req.session.admin, items, userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS });
  } catch (e) {
    console.error(e);
    res.status(500).send("خطأ في تحميل قائمة الشرف");
  }
});

app.get("/admin/honor/new", isAuthed, requirePermission("honor"), async (req, res) => {
  const persons = await getAdminPersonOptions();
  res.render("honor_form", { admin: req.session.admin, mode: "new", item: null, persons, userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS });
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

    const persons = await getAdminPersonOptions();
    res.render("honor_form", { admin: req.session.admin, mode: "edit", item, persons, userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS });
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

app.get("/admin/chats", isAuthed, requirePermission("chats"), async (req, res) => {
  try {
    const publicThread = await ensurePublicChatThread();
    const stats = {
      totalMessages: (await get(`SELECT COUNT(*) AS total FROM site_chat_messages WHERE COALESCE(is_deleted,0)=0`))?.total || 0,
      publicMessages: (await get(`SELECT COUNT(*) AS total FROM site_chat_messages WHERE thread_id=? AND COALESCE(is_deleted,0)=0`, [publicThread.id]))?.total || 0,
      privateThreads: (await get(`SELECT COUNT(*) AS total FROM site_chat_threads WHERE type='private' AND COALESCE(is_active,1)=1`))?.total || 0,
      deletedMessages: (await get(`SELECT COUNT(*) AS total FROM site_chat_deleted_archive`))?.total || 0,
      reportsCount: (await get(`SELECT COUNT(*) AS total FROM site_chat_message_reports WHERE status='pending'`))?.total || 0,
      blockedUsers: (await get(`SELECT COUNT(*) AS total FROM site_chat_blocks WHERE COALESCE(is_active,1)=1`))?.total || 0,
    };
    const latestMessages = await all(
      `SELECT m.*, t.type AS thread_type, t.title AS thread_title, u.full_name AS sender_name, u.email AS sender_email
       FROM site_chat_messages m
       JOIN site_chat_threads t ON t.id = m.thread_id
       LEFT JOIN site_users u ON u.id = m.sender_user_id
       WHERE COALESCE(m.is_deleted,0)=0
       ORDER BY m.id DESC
       LIMIT 120`
    ).catch(() => []);
    const reports = await all(`SELECT r.*, m.body, m.message_type, m.attachment_url, m.sender_user_id AS sender_user_id, reporter.full_name AS reporter_name, sender.full_name AS sender_name
       FROM site_chat_message_reports r
       LEFT JOIN site_chat_messages m ON m.id=r.message_id
       LEFT JOIN site_users reporter ON reporter.id=r.reporter_user_id
       LEFT JOIN site_users sender ON sender.id=m.sender_user_id
       WHERE r.status='pending'
       ORDER BY r.id DESC LIMIT 80`).catch(() => []);
    const blockedUsers = await all(`SELECT b.*, u.full_name, u.email, u.avatar_url
       FROM site_chat_blocks b
       JOIN site_users u ON u.id=b.user_id
       WHERE COALESCE(b.is_active,1)=1
       ORDER BY b.updated_at DESC LIMIT 80`).catch(() => []);
    const archivedMessages = await all(`SELECT a.*, u.full_name AS sender_name
       FROM site_chat_deleted_archive a
       LEFT JOIN site_users u ON u.id=a.sender_user_id
       ORDER BY a.id DESC LIMIT 80`).catch(() => []);
    const allUsers = await all(`SELECT id, full_name, father_name, email FROM site_users WHERE COALESCE(is_active,1)=1 ORDER BY full_name ASC LIMIT 500`).catch(() => []);
    const chatSettings = { bannedWords: (await get(`SELECT value FROM site_settings WHERE key='chat_banned_words'`).catch(() => ({value:''}))).value || "" };
    const threads = await all(
      `SELECT t.id, t.type, t.is_locked, t.is_active, t.updated_at,
              COUNT(m.id) AS messages_count,
              GROUP_CONCAT(u.full_name, ' × ') AS participants
       FROM site_chat_threads t
       LEFT JOIN site_chat_participants p ON p.thread_id=t.id
       LEFT JOIN site_users u ON u.id=p.user_id
       LEFT JOIN site_chat_messages m ON m.thread_id=t.id AND COALESCE(m.is_deleted,0)=0
       WHERE t.type='private'
       GROUP BY t.id
       ORDER BY t.updated_at DESC
       LIMIT 80`
    ).catch(() => []);
    res.render("admin_chats", { admin: req.session.admin, publicThread, stats, latestMessages, threads, reports, blockedUsers, archivedMessages, allUsers, chatSettings, userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل إدارة المحادثات");
  }
});

app.post("/admin/chats/public/toggle", isAuthed, requirePermission("chats"), async (req, res) => {
  try {
    const publicThread = await ensurePublicChatThread();
    const next = Number(publicThread.is_locked) === 1 ? 0 : 1;
    await run(`UPDATE site_chat_threads SET is_locked=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [next, publicThread.id]);
    res.redirect("/admin/chats");
  } catch (e) {
    console.error(e);
    res.redirect("/admin/chats");
  }
});

app.post("/admin/chats/messages/:id/delete", isAuthed, requirePermission("chats"), async (req, res) => {
  try {
    const message = await archiveChatMessageBeforeDelete(req.params.id, req.session.admin?.id);
    await run(`DELETE FROM site_chat_messages WHERE id=?`, [req.params.id]);
    if (message?.thread_id) emitChatThreadUpdate(message.thread_id, "delete", { messageId: Number(req.params.id) });
    await logAdminAction(req, "حذف رسالة نهائيًا مع أرشفة إدارية", "chat_message", req.params.id, {});
    res.redirect(req.headers.referer || "/admin/chats");
  } catch (e) {
    console.error(e);
    res.redirect("/admin/chats");
  }
});

app.post("/admin/chats/threads/:id/toggle", isAuthed, requirePermission("chats"), async (req, res) => {
  try {
    const thread = await get(`SELECT * FROM site_chat_threads WHERE id=?`, [req.params.id]);
    if (thread && thread.type !== "public") {
      const next = Number(thread.is_active) === 1 ? 0 : 1;
      await run(`UPDATE site_chat_threads SET is_active=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [next, thread.id]);
    }
    res.redirect(req.headers.referer || "/admin/chats");
  } catch (e) {
    console.error(e);
    res.redirect("/admin/chats");
  }
});


app.post("/admin/chats/settings", isAuthed, requirePermission("chats"), async (req, res) => {
  try {
    const bannedWords = cleanText(req.body.banned_words || "", 3000);
    const exists = await get(`SELECT key FROM site_settings WHERE key='chat_banned_words'`).catch(() => null);
    if (exists) await run(`UPDATE site_settings SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key='chat_banned_words'`, [bannedWords]);
    else await run(`INSERT INTO site_settings (key, value, updated_at) VALUES ('chat_banned_words', ?, CURRENT_TIMESTAMP)`, [bannedWords]);
    await logAdminAction(req, "تحديث فلترة كلمات الشات", "chat_settings", "chat_banned_words", {});
    res.redirect("/admin/chats");
  } catch (e) { console.error(e); res.redirect("/admin/chats"); }
});

app.post("/admin/chats/users/:id/block", isAuthed, requireAnyPermission(["chats", "users"]), async (req, res) => {
  try {
    const userId = Number(req.params.id || 0);
    const reason = cleanText(req.body.reason || "", 500);
    if (userId) {
      await run(`INSERT INTO site_chat_blocks (user_id, blocked_by_admin_id, reason, is_active, created_at, updated_at)
                 VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                 ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason, blocked_by_admin_id=excluded.blocked_by_admin_id, is_active=1, updated_at=CURRENT_TIMESTAMP`, [userId, req.session.admin?.id || null, reason]);
      await logAdminAction(req, "حظر مستخدم من الشات", "site_user", userId, { reason });
    }
    res.redirect(req.headers.referer || "/admin/chats");
  } catch (e) { console.error(e); res.redirect("/admin/chats"); }
});

app.post("/admin/chats/users/:id/unblock", isAuthed, requireAnyPermission(["chats", "users"]), async (req, res) => {
  try {
    await run(`UPDATE site_chat_blocks SET is_active=0, updated_at=CURRENT_TIMESTAMP WHERE user_id=?`, [req.params.id]);
    await logAdminAction(req, "رفع حظر مستخدم من الشات", "site_user", req.params.id, {});
    res.redirect(req.headers.referer || "/admin/chats");
  } catch (e) { console.error(e); res.redirect("/admin/chats"); }
});

app.post("/admin/chats/reports/:id/review", isAuthed, requirePermission("chats"), async (req, res) => {
  try {
    await run(`UPDATE site_chat_message_reports SET status='reviewed', reviewed_by_admin_id=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`, [req.session.admin?.id || null, req.params.id]);
    await logAdminAction(req, "مراجعة بلاغ رسالة", "chat_report", req.params.id, {});
    res.redirect(req.headers.referer || "/admin/chats");
  } catch (e) { console.error(e); res.redirect("/admin/chats"); }
});

app.get("/admin/users", isAuthed, requirePermission("users"), async (req, res) => {
  try {
    const q = cleanText(req.query.q || "", 160);
    const params = [];
    let where = "";
    if (q) {
      where = `WHERE full_name LIKE ? OR father_name LIKE ? OR mother_name LIKE ? OR email LIKE ? OR phone LIKE ? OR country LIKE ? OR city LIKE ? OR current_residence LIKE ? OR origin_place LIKE ?`;
      const like = `%${q}%`;
      params.push(like, like, like, like, like, like, like, like, like);
    }

    const users = await all(
      `SELECT u.*,
              (SELECT COUNT(*) FROM site_user_activity_logs l WHERE l.user_id = u.id) AS activity_count,
              (SELECT MAX(created_at) FROM site_user_activity_logs l WHERE l.user_id = u.id) AS last_activity_at,
              EXISTS(SELECT 1 FROM site_chat_blocks b WHERE b.user_id = u.id AND COALESCE(b.is_active,1)=1) AS chat_blocked
       FROM site_users u
       ${where}
       ORDER BY COALESCE(u.last_seen_at, u.last_login_at, u.created_at) DESC, u.id DESC
       LIMIT 200`,
      params
    );

    const stats = {
      total: (await get(`SELECT COUNT(*) AS total FROM site_users`))?.total || 0,
      active: (await get(`SELECT COUNT(*) AS total FROM site_users WHERE COALESCE(is_active,1)=1`))?.total || 0,
      inactive: (await get(`SELECT COUNT(*) AS total FROM site_users WHERE COALESCE(is_active,1)=0`))?.total || 0,
      google: (await get(`SELECT COUNT(*) AS total FROM site_users WHERE provider='google'`))?.total || 0,
      email: (await get(`SELECT COUNT(*) AS total FROM site_users WHERE COALESCE(provider,'email')='email'`))?.total || 0,
      today: (await get(`SELECT COUNT(*) AS total FROM site_users WHERE date(created_at)=date('now')`))?.total || 0,
    };

    const latestActivity = await all(
      `SELECT l.*, u.full_name, u.email
       FROM site_user_activity_logs l
       LEFT JOIN site_users u ON u.id = l.user_id
       ORDER BY l.id DESC
       LIMIT 80`
    );

    res.render("admin_users", { admin: req.session.admin, users, stats, latestActivity, q, deleted: req.query.deleted === "1", userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل مستخدمي الموقع");
  }
});

app.get("/admin/users/:id", isAuthed, requirePermission("users"), async (req, res) => {
  try {
    const user = await get(`SELECT * FROM site_users WHERE id = ?`, [req.params.id]);
    if (!user) return res.status(404).send("المستخدم غير موجود");
    const chatBlock = await get(`SELECT * FROM site_chat_blocks WHERE user_id=? AND COALESCE(is_active,1)=1 LIMIT 1`, [user.id]).catch(() => null);
    const activity = await all(`SELECT * FROM site_user_activity_logs WHERE user_id = ? ORDER BY id DESC LIMIT 250`, [user.id]);
    const stats = await getSiteUserProfileStats(user.id);
    const treePerson = await findTreePersonForSiteUser(user);
    const honorItem = await findHonorForUser(user, treePerson);
    const profileViews = await all(
      `SELECT v.*, viewer.full_name AS viewer_name, viewer.email AS viewer_email
       FROM site_profile_views v
       LEFT JOIN site_users viewer ON viewer.id = v.viewer_user_id
       WHERE v.profile_user_id = ?
       ORDER BY v.id DESC
       LIMIT 80`,
      [user.id]
    ).catch(() => []);
    res.render("admin_user_detail", { admin: req.session.admin, user, chatBlock, activity, stats, treePerson, honorItem, profileViews, userCan: (perm) => userCan(req.session.admin, perm), permissionGroups: PERMISSION_GROUPS });
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تحميل بيانات المستخدم");
  }
});

app.post("/admin/users/:id/toggle", isAuthed, requirePermission("users"), async (req, res) => {
  try {
    const user = await get(`SELECT * FROM site_users WHERE id = ?`, [req.params.id]);
    if (!user) return res.status(404).send("المستخدم غير موجود");
    const chatBlock = await get(`SELECT * FROM site_chat_blocks WHERE user_id=? AND COALESCE(is_active,1)=1 LIMIT 1`, [user.id]).catch(() => null);
    const nextActive = Number(user.is_active) === 1 ? 0 : 1;
    await run(`UPDATE site_users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [nextActive, user.id]);
    await logAdminAction(req, nextActive ? "تفعيل مستخدم موقع" : "إيقاف مستخدم موقع", "site_user", user.id, { email: user.email });
    res.redirect(req.headers.referer || "/admin/users");
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء تعديل حالة المستخدم");
  }
});


// حذف حساب مستخدم من مركز الحسابات بالكامل. بعد الحذف لن يستطيع الدخول بالحساب القديم، ويمكنه التسجيل من جديد كحساب جديد.
app.post("/admin/users/:id/delete", isAuthed, requirePermission("users"), async (req, res) => {
  try {
    const userId = Number(req.params.id || 0);
    if (!userId) return res.status(400).send("حساب غير صحيح");
    const user = await get(`SELECT * FROM site_users WHERE id = ?`, [userId]);
    if (!user) return res.status(404).send("المستخدم غير موجود");

    await removeUploadedFileByUrl(user.avatar_url).catch(() => {});
    await removeUploadedFileByUrl(user.cover_url).catch(() => {});

    await run(`DELETE FROM site_notifications WHERE user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM site_profile_views WHERE profile_user_id=? OR viewer_user_id=?`, [userId, userId]).catch(() => {});
    await run(`DELETE FROM site_user_activity_logs WHERE user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM site_user_tree_link_requests WHERE user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM site_reports WHERE reporter_user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM family_events WHERE submitted_by_user_id=? AND COALESCE(status,'pending') <> 'approved'`, [userId]).catch(() => {});
    await run(`DELETE FROM family_gallery_items WHERE submitted_by_user_id=? AND COALESCE(status,'pending') <> 'approved'`, [userId]).catch(() => {});
    await run(`DELETE FROM tree_edit_suggestions WHERE submitted_by_user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM site_chat_blocks WHERE user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM site_chat_message_reports WHERE reporter_user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM site_chat_participants WHERE user_id=?`, [userId]).catch(() => {});
    await run(`UPDATE site_chat_messages SET sender_user_id=NULL, updated_at=CURRENT_TIMESTAMP WHERE sender_user_id=?`, [userId]).catch(() => {});
    await run(`DELETE FROM site_users WHERE id=?`, [userId]);

    await logAdminAction(req, "حذف حساب مستخدم موقع", "site_user", userId, { email: user.email || "", name: user.full_name || "" });
    res.redirect("/admin/users?deleted=1");
  } catch (e) {
    console.error(e);
    res.status(500).send("حدث خطأ أثناء حذف الحساب");
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
   Family Platform Advanced Features
   ========================= */

app.get("/account-pending", async (req, res) => {
  const user = req.session?.siteUser?.id ? await getSiteUserById(req.session.siteUser.id).catch(() => null) : null;
  if (!user) return res.redirect("/login");
  if ((user.approval_status || "approved") === "approved") return res.redirect("/");
  res.status(403).render("user_pending", { siteUser: publicSiteUserSession(user), user, status: user.approval_status || "pending", reason: user.rejected_reason || "" });
});

app.get("/notifications", async (req, res) => {
  const userId = Number(req.session.siteUser.id);
  const notifications = await all(`SELECT * FROM site_notifications WHERE user_id=? ORDER BY id DESC LIMIT 100`, [userId]).catch(() => []);
  res.render("notifications", { active:"notifications", siteUser:req.session.siteUser, notifications });
});

app.post("/notifications/read-all", async (req, res) => {
  const userId = Number(req.session.siteUser.id);
  await run(`UPDATE site_notifications SET is_read=1, read_at=CURRENT_TIMESTAMP WHERE user_id=? AND COALESCE(is_read,0)=0`, [userId]).catch(() => {});
  res.redirect("/notifications");
});

app.get("/api/notifications/unread", async (req, res) => {
  try {
    const userId = Number(req.session?.siteUser?.id || 0);
    if (!userId) return res.status(401).json({ ok:false, unread:0 });
    res.json({ ok:true, unread: await unreadNotificationsCount(userId) });
  } catch(e) { res.json({ ok:false, unread:0 }); }
});

app.post("/account/link-request", async (req, res) => {
  try {
    const userId = Number(req.session.siteUser.id);
    const lineage = cleanText(req.body.lineage_text || "", 220);
    if (!lineage || namePartsForMatch(lineage).length < 3) {
      return res.redirect("/account?error=" + encodeURIComponent("اكتب الاسم الثلاثي أو الرباعي كما تريد مراجعته من الإدارة."));
    }
    const exists = await get(`SELECT id FROM site_user_tree_link_requests WHERE user_id=? AND status='pending' LIMIT 1`, [userId]).catch(() => null);
    if (exists) return res.redirect("/account?error=" + encodeURIComponent("لديك طلب ربط قيد المراجعة بالفعل."));

    const resolved = await resolvePersonByThreePartLineage(lineage).catch(() => ({ ok:false, id:null, status:"error", message:"تعذر الاستعلام عن الاسم" }));
    const inserted = await run(
      `INSERT INTO site_user_tree_link_requests
       (user_id, requested_person_id, lineage_text, match_status, match_message, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [userId, resolved.ok ? resolved.id : null, lineage, resolved.status || (resolved.ok ? "matched" : "not_found"), resolved.ok ? "الاسم موجود في الشجرة ويمكن ربطه" : (resolved.message || "الاسم غير موجود أو به خطأ" )]
    );
    const requestId = inserted?.lastID || null;
    await createNotification(
      userId,
      "تم إرسال طلب ربط الحساب بالشجرة",
      resolved.ok
        ? "وصل طلبك للإدارة، والاسم موجود داخل الشجرة ويمكن ربطه بعد اعتماد المسؤول."
        : "وصل طلبك للإدارة، وسيتم مراجعته حتى لو ظهر أن الاسم غير موجود أو يحتاج تصحيح.",
      "/account",
      "tree_link_request"
    );
    await logSiteUserActivity(req, "طلب ربط الحساب بالشجرة", { requestId, personId: resolved.ok ? resolved.id : null, lineage, matchStatus: resolved.status });
    await logAdminAction(req, "طلب ربط حساب بالشجرة", "site_user_tree_link_request", requestId || userId, { lineage, matchStatus: resolved.status, userId }).catch(() => {});
    res.redirect("/account?success=" + encodeURIComponent("تم إرسال طلب الربط للإدارة. ستصلك نتيجة المراجعة في الإشعارات."));
  } catch(e) { console.error(e); res.redirect("/account?error=" + encodeURIComponent("تعذر إرسال طلب الربط")); }
});

app.get("/events", async (req, res) => {
  const events = await all(`SELECT e.*, u.full_name AS submitter_name FROM family_events e LEFT JOIN site_users u ON u.id=e.submitted_by_user_id WHERE e.status='approved' ORDER BY COALESCE(e.event_date,e.created_at) DESC LIMIT 200`).catch(() => []);
  res.render("family_events", { active:"events", siteUser:req.session.siteUser, events, success:req.query.success || null, error:req.query.error || null });
});

app.post("/events", upload.single("image_file"), async (req, res) => {
  try {
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : "";
    const title = cleanText(req.body.title, 180);
    if (!title) return res.redirect("/events?error=" + encodeURIComponent("عنوان المناسبة مطلوب."));
    await run(`INSERT INTO family_events (submitted_by_user_id, title, event_type, event_date, location, description, image_url, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, [req.session.siteUser.id, title, cleanText(req.body.event_type,80), cleanText(req.body.event_date,40), cleanText(req.body.location,180), cleanText(req.body.description,1500), imageUrl]);
    await logSiteUserActivity(req, "إرسال مناسبة للمراجعة", { title });
    res.redirect("/events?success=" + encodeURIComponent("تم إرسال المناسبة وستظهر بعد موافقة الإدارة."));
  } catch(e) { console.error(e); res.redirect("/events?error=" + encodeURIComponent("تعذر إرسال المناسبة.")); }
});

app.get("/gallery", async (req, res) => {
  const items = await all(`SELECT g.*, u.full_name AS submitter_name FROM family_gallery_items g LEFT JOIN site_users u ON u.id=g.submitted_by_user_id WHERE g.status='approved' ORDER BY g.id DESC LIMIT 240`).catch(() => []);
  res.render("family_gallery", { active:"gallery", siteUser:req.session.siteUser, items, success:req.query.success || null, error:req.query.error || null });
});

app.post("/gallery", upload.single("image_file"), async (req, res) => {
  try {
    if (!req.file) return res.redirect("/gallery?error=" + encodeURIComponent("اختر صورة للرفع."));
    await run(`INSERT INTO family_gallery_items (submitted_by_user_id, title, category, image_url, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, [req.session.siteUser.id, cleanText(req.body.title,180), cleanText(req.body.category,80), `/uploads/${req.file.filename}`, cleanText(req.body.description,1000)]);
    await logSiteUserActivity(req, "إرسال صورة للمعرض", {});
    res.redirect("/gallery?success=" + encodeURIComponent("تم رفع الصورة وستظهر بعد موافقة الإدارة."));
  } catch(e) { console.error(e); res.redirect("/gallery?error=" + encodeURIComponent("تعذر رفع الصورة.")); }
});

app.post("/family-members/:id/report", async (req, res) => {
  try {
    const targetId = Number(req.params.id || 0);
    if (!targetId || targetId === Number(req.session.siteUser.id)) return res.redirect("/family-members");
    await run(`INSERT INTO site_reports (reporter_user_id, target_type, target_id, reason, details, status, created_at) VALUES (?, 'user', ?, ?, ?, 'pending', CURRENT_TIMESTAMP)`, [req.session.siteUser.id, targetId, cleanText(req.body.reason,180) || "بلاغ عن حساب", cleanText(req.body.details,1000)]);
    await logSiteUserActivity(req, "بلاغ عن حساب", { targetId });
    res.redirect(`/family-members/${targetId}?reported=1`);
  } catch(e) { console.error(e); res.redirect("/family-members"); }
});

app.post("/suggest-edit", async (req, res) => {
  try {
    const personId = Number(req.body.person_id || 0);
    if (!personId) return res.redirect("/?error=suggestion");
    await run(`INSERT INTO tree_edit_suggestions (submitted_by_user_id, person_id, field_name, current_value, suggested_value, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)`, [req.session.siteUser.id, personId, cleanText(req.body.field_name,80), cleanText(req.body.current_value,500), cleanText(req.body.suggested_value,500), cleanText(req.body.reason,1000)]);
    res.redirect("/?suggested=1");
  } catch(e) { console.error(e); res.redirect("/"); }
});

app.get("/family-books", async (req, res) => {
  const roots = await all(`SELECT p.*, (SELECT COUNT(*) FROM persons c WHERE c.father_id=p.id OR c.mother_id=p.id) AS children_count FROM persons p WHERE p.father_id IS NULL OR p.father_id='' ORDER BY p.id ASC LIMIT 80`).catch(() => []);
  res.render("family_books", { active:"books", siteUser:req.session.siteUser, roots });
});

app.get("/family-books/:id", async (req, res) => {
  const root = await get(`SELECT * FROM persons WHERE id=?`, [req.params.id]).catch(() => null);
  if (!root) return res.status(404).send("الفرع غير موجود");
  const members = await all(`SELECT * FROM persons WHERE id=? OR father_id=? OR mother_id=? ORDER BY birth_date, id`, [root.id, root.id, root.id]).catch(() => []);
  res.render("family_book_detail", { active:"books", siteUser:req.session.siteUser, root, members });
});

app.get("/admin/approvals", isAuthed, requireAnyPermission(["approvals", "users", "events", "gallery", "reports"]), async (req, res) => {
  try {
    const pendingUsers = await all(`SELECT * FROM site_users WHERE approval_status='pending' ORDER BY id DESC LIMIT 100`).catch(() => []);
    const linkRequests = await all(`SELECT r.*, u.full_name, u.email, u.phone, p.name AS person_name FROM site_user_tree_link_requests r LEFT JOIN site_users u ON u.id=r.user_id LEFT JOIN persons p ON p.id=r.requested_person_id WHERE r.status='pending' ORDER BY r.id DESC LIMIT 100`).catch(() => []);
    const reports = await all(`SELECT r.*, u.full_name AS reporter_name FROM site_reports r LEFT JOIN site_users u ON u.id=r.reporter_user_id WHERE r.status='pending' ORDER BY r.id DESC LIMIT 100`).catch(() => []);
    const events = await all(`SELECT e.*, u.full_name AS submitter_name FROM family_events e LEFT JOIN site_users u ON u.id=e.submitted_by_user_id WHERE e.status='pending' ORDER BY e.id DESC LIMIT 100`).catch(() => []);
    const gallery = await all(`SELECT g.*, u.full_name AS submitter_name FROM family_gallery_items g LEFT JOIN site_users u ON u.id=g.submitted_by_user_id WHERE g.status='pending' ORDER BY g.id DESC LIMIT 100`).catch(() => []);
    const suggestions = await all(`SELECT s.*, u.full_name AS submitter_name, p.name AS person_name FROM tree_edit_suggestions s LEFT JOIN site_users u ON u.id=s.submitted_by_user_id LEFT JOIN persons p ON p.id=s.person_id WHERE s.status='pending' ORDER BY s.id DESC LIMIT 100`).catch(() => []);
    const invites = await all(`SELECT * FROM site_invite_codes ORDER BY id DESC LIMIT 60`).catch(() => []);
    res.render("admin_approvals", { admin:req.session.admin, pendingUsers, linkRequests, reports, events, gallery, suggestions, invites, userCan:(perm)=>userCan(req.session.admin, perm), permissionGroups:PERMISSION_GROUPS });
  } catch(e) { console.error(e); res.status(500).send("حدث خطأ أثناء تحميل مركز الموافقات"); }
});

app.post("/admin/users/:id/approval", isAuthed, requireAnyPermission(["approvals", "users"]), async (req, res) => {
  try {
    const userId = Number(req.params.id || 0);
    const action = String(req.body.action || "");
    const status = action === "approve" ? "approved" : action === "reject" ? "rejected" : action === "block" ? "blocked" : "pending";
    await run(`UPDATE site_users SET approval_status=?, approved_by_admin_id=?, approved_at=CASE WHEN ?='approved' THEN CURRENT_TIMESTAMP ELSE approved_at END, rejected_reason=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [status, req.session.admin?.id || null, status, cleanText(req.body.reason,500), userId]);
    await createNotification(userId, status === "approved" ? "تم قبول حسابك" : "تم تحديث حالة حسابك", status === "approved" ? "يمكنك الآن استخدام الموقع." : (cleanText(req.body.reason,500) || "راجعت الإدارة حسابك."), status === "approved" ? "/" : "/account-pending", "account_approval");
    await logAdminAction(req, "تحديث حالة حساب مستخدم", "site_user", userId, { status });
    res.redirect(req.headers.referer || "/admin/approvals");
  } catch(e) { console.error(e); res.redirect("/admin/approvals"); }
});

app.post("/admin/link-requests/:id/review", isAuthed, requireAnyPermission(["approvals", "users"]), async (req, res) => {
  try {
    const id = Number(req.params.id || 0);
    const action = String(req.body.action || "");
    const r = await get(`SELECT * FROM site_user_tree_link_requests WHERE id=?`, [id]);
    if (r) {
      let status = action === "approve" ? "approved" : "rejected";
      if (status === "approved" && !Number(r.requested_person_id || 0)) status = "rejected";
      const adminNote = cleanText(req.body.admin_note, 500);
      await run(`UPDATE site_user_tree_link_requests SET status=?, admin_note=?, reviewed_by_admin_id=?, reviewed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [status, adminNote, req.session.admin?.id || null, id]);
      if (status === "approved") {
        await run(`UPDATE site_users SET matched_person_id=?, verification_status='verified', updated_at=CURRENT_TIMESTAMP WHERE id=?`, [r.requested_person_id, r.user_id]);
        await createNotification(r.user_id, "تم ربط اسمك في الشجرة التفاعلية", "تم ربط حسابك ببطاقتك داخل الشجرة. يمكنك الآن الضغط على شاهد موقعك في الشجرة من صفحة حسابك.", `/?focus=${encodeURIComponent(r.requested_person_id)}`, "tree_link");
        await logAdminAction(req, "قبول وربط حساب بالشجرة", "site_user_tree_link_request", id, { personId: r.requested_person_id });
      } else {
        await createNotification(r.user_id, "لم يتم ربط الاسم بالشجرة", adminNote || "للأسف لم يتم ربط الاسم لعدم وجوده في الشجرة أو لوجود خطأ في الاسم. يرجى إضافة البيانات من صفحة إضافة بياناتك ثم إعادة محاولة الربط. شكراً.", "/submit-person", "tree_link");
        await logAdminAction(req, "رفض طلب ربط حساب بالشجرة", "site_user_tree_link_request", id, { reason: adminNote });
      }
    }
    res.redirect(req.headers.referer || "/admin/approvals");
  } catch(e) { console.error(e); res.redirect("/admin/approvals"); }
});

app.post("/admin/content/:type/:id/review", isAuthed, requireAnyPermission(["approvals", "events", "gallery", "reports"]), async (req, res) => {
  try {
    const type = String(req.params.type || "");
    const id = Number(req.params.id || 0);
    const action = String(req.body.action || "");
    const status = action === "approve" ? "approved" : action === "reject" ? "rejected" : "reviewed";
    const tableMap = { event:"family_events", gallery:"family_gallery_items", report:"site_reports", suggestion:"tree_edit_suggestions" };
    const table = tableMap[type];
    if (table && id) {
      if (type === "report") await run(`UPDATE site_reports SET status=?, reviewed_by_admin_id=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`, [status === "approved" ? "reviewed" : status, req.session.admin?.id || null, id]);
      else await run(`UPDATE ${table} SET status=?, reviewed_by_admin_id=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`, [status, req.session.admin?.id || null, id]);
      await logAdminAction(req, "مراجعة محتوى مرسل", type, id, { status });
    }
    res.redirect(req.headers.referer || "/admin/approvals");
  } catch(e) { console.error(e); res.redirect("/admin/approvals"); }
});

app.post("/admin/invites", isAuthed, requireAnyPermission(["approvals", "users"]), async (req, res) => {
  try {
    const code = (cleanText(req.body.code,80) || ("FAMILY-" + crypto.randomBytes(3).toString("hex"))).toUpperCase();
    await run(`INSERT INTO site_invite_codes (code, note, max_uses, expires_at, is_active, created_by_admin_id, created_at) VALUES (?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP)`, [code, cleanText(req.body.note,300), Number(req.body.max_uses || 1), cleanText(req.body.expires_at,40), req.session.admin?.id || null]);
    res.redirect("/admin/approvals#invites");
  } catch(e) { console.error(e); res.redirect("/admin/approvals#invites"); }
});

app.get("/admin/events", isAuthed, requireAnyPermission(["events", "approvals"]), (req, res) => res.redirect("/admin/approvals#events"));
app.get("/admin/gallery", isAuthed, requireAnyPermission(["gallery", "approvals"]), (req, res) => res.redirect("/admin/approvals#gallery"));

app.get("/admin/backups", isAuthed, requirePermission("backups"), async (req, res) => {
  res.render("admin_backups", { admin:req.session.admin, userCan:(perm)=>userCan(req.session.admin, perm), permissionGroups:PERMISSION_GROUPS, error:req.query.error || null });
});

app.get("/admin/backups/download", isAuthed, requirePermission("backups"), async (req, res) => {
  try {
    const archiver = require("archiver");
    const filename = `family-tree-backup-${new Date().toISOString().slice(0,10)}.zip`;
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.on("error", err => { throw err; });
    archive.pipe(res);
    if (fs.existsSync(path.join(__dirname, "family.db"))) archive.file(path.join(__dirname, "family.db"), { name: "family.db" });
    if (fs.existsSync(path.join(__dirname, "sessions.db"))) archive.file(path.join(__dirname, "sessions.db"), { name: "sessions.db" });
    if (fs.existsSync(path.join(__dirname, "public", "uploads"))) archive.directory(path.join(__dirname, "public", "uploads"), "public/uploads");
    archive.append(JSON.stringify({ created_at:new Date().toISOString(), app:"family-tree" }, null, 2), { name:"backup-info.json" });
    await logAdminAction(req, "تنزيل نسخة احتياطية", "backup", filename, {});
    archive.finalize();
  } catch(e) {
    console.error(e);
    res.redirect("/admin/backups?error=" + encodeURIComponent("ثبّت archiver أولًا عبر npm install أو شغّل npm install بعد التحديث."));
  }
});


app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || /يسمح|Only PDF|File too large|حجم الملف/i.test(String(err?.message || ""))) {
    const message = err.code === "LIMIT_FILE_SIZE" ? "حجم الملف أكبر من الحد المسموح." : (err.message || "نوع الملف غير مسموح.");
    if (req.path === "/account") return res.redirect("/account?error=" + encodeURIComponent(message));
    if (req.path === "/register") return res.redirect("/register?error=" + encodeURIComponent(message));
    if (req.path.startsWith("/api/")) return res.status(400).json({ ok:false, message });
    const back = req.headers.referer || "/";
    const safeMessage = String(message).replace(/[<>&]/g, "");
    return res.status(400).send(`<div dir="rtl" style="font-family:Arial;padding:40px;text-align:center"><h2>تعذر رفع الملف</h2><p>${safeMessage}</p><a href="${back}">العودة</a></div>`);
  }
  return next(err);
});

/* =========================
   404
   ========================= */
app.use((req, res) => {
  res.status(404).send("الصفحة غير موجودة");
});

const PORT = process.env.PORT || 3000;
if (SocketIOServer) {
  io = new SocketIOServer(server, { path: "/socket.io" });
  io.on("connection", (socket) => {
    socket.on("join-chat-thread", (threadId) => {
      const id = Number(threadId || 0);
      if (id) socket.join(`chat-thread:${id}`);
    });
  });
} else {
  console.warn("Socket.IO is not installed; chat will keep using safe polling fallback. Run: npm install socket.io");
}
server.listen(PORT, () => console.log("Running on", PORT));
