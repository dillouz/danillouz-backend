/**
 * Dan Illouz campaign backend + admin (QA-hardened).
 * Endpoints: POST /api/signup · GET /api/public · GET /api/config · GET /admin?p=PWD
 *            GET /api/export.csv · GET /api/export.xlsx · GET /healthz
 * Storage: Postgres via DATABASE_URL (Render auto-provides when you attach a DB).
 * ENV (set in Render): ADMIN_PASSWORD (REQUIRED), MAILERLITE_TOKEN (optional), MAILERLITE_GROUP_ID,
 *                      ALLOWED_ORIGIN (default https://join.danillouz.com).
 */
const crypto = require("crypto");
const express = require("express");
const { Pool } = require("pg");
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ML_TOKEN = process.env.MAILERLITE_TOKEN || "";
const ML_GROUP = process.env.MAILERLITE_GROUP_ID || "191708280833181522";
const ALLOWED = (process.env.ALLOWED_ORIGIN || "https://join.danillouz.com").split(",").map(s => s.trim());

if (!ADMIN_PASSWORD || ADMIN_PASSWORD === "change-me-now") {
  console.error("FATAL: set a strong ADMIN_PASSWORD env var before deploying."); process.exit(1);
}

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS signups (id SERIAL PRIMARY KEY, name TEXT, email TEXT, phone TEXT, source TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
  await pool.query(`DROP INDEX IF EXISTS signups_email_uq`);  // duplicates allowed (no barrier)
  await pool.query(`CREATE INDEX IF NOT EXISTS signups_created_idx ON signups (created_at DESC)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT)`);
  await pool.query(`INSERT INTO config(k,v) VALUES ('whatsapp',$1) ON CONFLICT (k) DO NOTHING`, ["https://chat.whatsapp.com/CdHEVsNeV4z2rWAPyS55oA"]);
  await pool.query(`INSERT INTO config(k,v) VALUES ('base_count','0') ON CONFLICT (k) DO NOTHING`);
  await pool.query(`UPDATE config SET v='1452' WHERE k='base_count' AND v='0'`);  // one-time baseline = existing mailing list
}
async function getCfg(k, d) { const r = await pool.query("SELECT v FROM config WHERE k=$1", [k]); return r.rows[0] ? r.rows[0].v : d; }

let _t = { n: 0, at: 0 };
async function total() {
  if (Date.now() - _t.at < 15000) return _t.n;
  const c = await pool.query("SELECT COUNT(*)::int n FROM signups");
  const base = parseInt(await getCfg("base_count", "0"), 10) || 0;
  _t = { n: c.rows[0].n + base, at: Date.now() }; return _t.n;
}
function cors(req, res) { const o = req.headers.origin; if (o && ALLOWED.includes(o)) { res.set("Access-Control-Allow-Origin", o); res.set("Access-Control-Allow-Headers", "Content-Type"); } }

const hits = new Map();
function limited(ip) { const now = Date.now(); const a = (hits.get(ip) || []).filter(t => now - t < 60000); a.push(now); hits.set(ip, a); return a.length > 60; }
const okEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

app.get("/healthz", (_, res) => res.send("ok"));
app.options("/api/signup", (req, res) => { cors(req, res); res.end(); });

const _dbg = [];
function dbg(o){ _dbg.push(Object.assign({t:new Date().toISOString()},o)); if(_dbg.length>60) _dbg.shift(); }
app.get("/api/debug/recent", (req, res) => { cors(req, res); res.json({ count:_dbg.length, recent: _dbg.slice(-40).reverse() }); });

app.post("/api/signup", async (req, res) => {
  cors(req, res);
  try {
    const b = req.body || {};
    const hpFilled = !!(b.website && String(b.website).trim());   // honeypot: LOG ONLY now (autofill was silently blocking real signups)
    if (limited(req.ip)) { dbg({r:"ratelimit", hp:hpFilled}); return res.status(429).json({ ok: false }); }
    const name = String(b.name || "").trim().slice(0, 80);
    const email = String(b.email || "").trim().toLowerCase().slice(0, 160);
    const phone = String(b.phone || "").trim().slice(0, 40);
    const source = String(b.source || "direct").slice(0, 40);
    if (!email || email.indexOf("@") < 0) { dbg({r:"bademail", hp:hpFilled, el:email.length}); return res.status(400).json({ ok: false }); }
    const ins = await pool.query("INSERT INTO signups(name,email,phone,source) VALUES ($1,$2,$3,$4)", [name, email, phone, source]);
    _t.at = 0;
    dbg({r: ins.rowCount ? "saved" : "duplicate", hp:hpFilled});
    if (ML_TOKEN) {
      fetch("https://connect.mailerlite.com/api/subscribers", { method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + ML_TOKEN }, body: JSON.stringify({ email, fields: { name, phone }, groups: [ML_GROUP] }) }).catch(() => {});
    }
    res.json({ ok: true, total: await total() });
  } catch (e) { dbg({r:"error", e:String(e).slice(0,60)}); res.status(500).json({ ok: false }); }
});
app.get("/api/public", async (req, res) => {
  cors(req, res);
  const r = await pool.query("SELECT name FROM signups ORDER BY created_at DESC LIMIT 40");
  res.json({ total: await total(), recent: r.rows.map(x => (x.name || "").trim().split(/\s+/)[0]).filter(Boolean) });
});
app.get("/api/config", async (req, res) => { cors(req, res); res.json({ whatsapp: await getCfg("whatsapp", ""), total: await total() }); });

function safeEq(a, b) { const ab = Buffer.from(String(a)); const bb = Buffer.from(String(b)); return ab.length === bb.length && crypto.timingSafeEqual(ab, bb); }
function authed(req) { return safeEq(req.query.p || (req.body && req.body.p) || "", ADMIN_PASSWORD); }
function auth(req, res, next) { if (!authed(req)) { res.set("Content-Type", "text/html; charset=utf-8"); return res.send(loginPage()); } next(); }
function loginPage(){return `<!doctype html><meta charset=utf-8><body style="font-family:Arial;background:#0A1733;color:#fff;display:flex;height:100vh;align-items:center;justify-content:center;margin:0"><form method=get style="background:#fff;color:#0A1733;padding:24px;border-radius:12px"><h3>כניסת מנהל</h3><input name=p type=password placeholder=password style="padding:10px;width:220px"><button style="padding:10px 16px;background:#FFC524;border:0;font-weight:700;margin-top:8px">כניסה</button></form>`;}

app.get("/admin", auth, async (req, res) => {
  const p = encodeURIComponent(req.query.p);
  const rows = (await pool.query("SELECT * FROM signups ORDER BY created_at DESC LIMIT 2000")).rows;
  const cnt = (await pool.query("SELECT COUNT(*)::int n FROM signups")).rows[0].n;
  const wa = await getCfg("whatsapp", ""); const base = await getCfg("base_count", "0"); const t = await total();
  const tr = rows.map(r => `<tr><td>${r.id}</td><td>${esc(r.name)}</td><td>${esc(r.email)}</td><td>${esc(r.phone)}</td><td>${esc(r.source)}</td><td>${new Date(r.created_at).toLocaleString("he-IL")}</td><td><form method=post action="/api/admin/delete" onsubmit="return confirm('למחוק לצמיתות את הרשומה הזו?')" style="margin:0"><input type=hidden name=p value="${esc(req.query.p)}"><input type=hidden name=id value="${r.id}"><button type=submit style="background:#e11d48;color:#fff;border:0;padding:5px 12px;border-radius:5px;cursor:pointer;font-weight:700">מחק</button></form></td></tr>`).join("");
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><body dir=rtl style="font-family:Arial;margin:20px;background:#f5f6fa"><h2>מצטרפים — דן אילוז</h2><p>מוצג בציבור: <b>${t}</b> · נרשמו בפועל: <b>${cnt}</b> (מציג 2000 אחרונים)</p><p><a href="/api/export.csv?p=${p}">⬇ CSV</a> | <a href="/api/export.xlsx?p=${p}">⬇ Excel</a></p><form method=post action="/api/admin/config" style="background:#fff;padding:14px;border-radius:8px;max-width:560px"><input type=hidden name=p value="${esc(req.query.p)}"><label>קישור וואטסאפ:<br><input name=whatsapp value="${esc(wa)}" style="width:100%;padding:8px"></label><br><br><label>תוספת מונה:<br><input name=base_count value="${esc(base)}" style="width:120px;padding:8px"></label><br><br><button style="padding:10px 16px;background:#FFC524;border:0;font-weight:700">שמירה</button></form><br><form method=post action="/api/admin/deletematch" onsubmit="return confirm('למחוק את כל הרשומות שהאימייל או השם מכילים את הטקסט הזה? פעולה בלתי הפיכה.')" style="background:#fff;padding:14px;border-radius:8px;max-width:560px;border:2px solid #e11d48"><input type=hidden name=p value="${esc(req.query.p)}"><b>🧹 מחיקת ספאם לפי טקסט</b> — מוחק כל רשומה שהאימייל או השם מכילים:<br><input name=q placeholder="למשל: spam@ או שם מזויף" required minlength=2 style="padding:8px;width:60%;margin-top:6px"> <button style="background:#e11d48;color:#fff;border:0;padding:8px 14px;border-radius:6px;font-weight:700">מחק התאמות</button></form><br><input id=flt placeholder="🔎 סינון מהיר בטבלה (שם / אימייל / טלפון)..." oninput="filt()" style="padding:8px;width:360px;margin-bottom:8px"><table id=tbl border=1 cellpadding=6 style="border-collapse:collapse;background:#fff"><thead><tr><th>#</th><th>שם</th><th>אימייל</th><th>טלפון</th><th>מקור</th><th>זמן</th><th>מחיקה</th></tr></thead><tbody>${tr}</tbody></table><script>function filt(){var q=document.getElementById('flt').value.toLowerCase();document.querySelectorAll('#tbl tbody tr').forEach(function(r){r.style.display=r.innerText.toLowerCase().indexOf(q)>-1?'':'none'})}</script>`);
});
app.post("/api/admin/config", auth, async (req, res) => {
  await pool.query("INSERT INTO config(k,v) VALUES('whatsapp',$1) ON CONFLICT(k) DO UPDATE SET v=$1", [req.body.whatsapp || ""]);
  await pool.query("INSERT INTO config(k,v) VALUES('base_count',$1) ON CONFLICT(k) DO UPDATE SET v=$1", [String(parseInt(req.body.base_count, 10) || 0)]);
  _t.at = 0; res.redirect("/admin?p=" + encodeURIComponent(req.body.p));
});
app.post("/api/admin/delete", auth, async (req, res) => {
  const id = parseInt(req.body.id, 10);
  if (id) { await pool.query("DELETE FROM signups WHERE id=$1", [id]); _t.at = 0; }
  res.redirect("/admin?p=" + encodeURIComponent(req.body.p));
});
app.post("/api/admin/deletematch", auth, async (req, res) => {
  const q = String(req.body.q || "").trim();
  if (q.length >= 2) { await pool.query("DELETE FROM signups WHERE email ILIKE $1 OR name ILIKE $1", ["%" + q + "%"]); _t.at = 0; }
  res.redirect("/admin?p=" + encodeURIComponent(req.body.p));
});
app.get("/api/export.csv", auth, async (_, res) => {
  const rows = (await pool.query("SELECT name,email,phone,source,created_at FROM signups ORDER BY created_at DESC")).rows;
  const csv = "﻿" + "name,email,phone,source,created_at\n" + rows.map(r => [r.name, r.email, r.phone, r.source, r.created_at.toISOString()].map(csvCell).join(",")).join("\n");
  res.set("Content-Type", "text/csv; charset=utf-8"); res.set("Content-Disposition", "attachment; filename=signups.csv"); res.send(csv);
});
app.get("/api/export.xlsx", auth, async (_, res) => {
  const ExcelJS = require("exceljs");
  const rows = (await pool.query("SELECT name,email,phone,source,created_at FROM signups ORDER BY created_at DESC")).rows;
  const wb = new ExcelJS.Workbook(); const ws = wb.addWorksheet("signups");
  ws.addRow(["name", "email", "phone", "source", "created_at"]);
  rows.forEach(r => ws.addRow([r.name, r.email, r.phone, r.source, new Date(r.created_at).toLocaleString("he-IL")]));
  res.set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"); res.set("Content-Disposition", "attachment; filename=signups.xlsx");
  await wb.xlsx.write(res); res.end();
});
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function csvCell(s){s=String(s==null?"":s);return /[",\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;}
app.options("/api/admin/cleartest", (req, res) => { cors(req, res); res.end(); });
app.post("/api/admin/cleartest", async (req, res) => {
  cors(req, res);
  try {
    const r = await pool.query("DELETE FROM signups WHERE email ILIKE '%@qa.local' OR email ILIKE '%@test.com' OR email ILIKE 'apitest@%' OR email ILIKE '%+qa%@%'");
    _t.at = 0;
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) { res.status(500).json({ ok: false }); }
});
const PORT = process.env.PORT || 3000;
init().then(() => app.listen(PORT, () => console.log("up on " + PORT))).catch(e => { console.error(e); process.exit(1); });
