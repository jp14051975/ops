/* Bots ops dashboard: static, no build. Data arrives only as data.enc.json
   (AES-256-GCM, key = PBKDF2-SHA256(passphrase, salt, iter)). Nothing personal lives in this file. */
"use strict";
var KEY_LS = "ops.pass", FACE_LS = "ops.face", REFRESH_MS = 60000, TZ = "Europe/London";
var keyCache = {};
/* Fixed 32-byte PRF salt (not secret; binds PRF eval to this app). */
var PRF_SALT = new Uint8Array([
  0x6f,0x70,0x73,0x2d,0x64,0x61,0x73,0x68,0x2d,0x70,0x72,0x66,0x2d,0x76,0x31,0x00,
  0xa7,0x3c,0x91,0x5e,0x22,0xb4,0x68,0x0d,0xf1,0x9a,0x44,0x7b,0xce,0x12,0x88,0x5d
]);

function b64(s) { var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
function b64enc(buf) {
  var u = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf, s = "";
  for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
function b64urlEnc(buf) {
  return b64enc(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDec(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return b64(s);
}
async function decryptEnvelope(env, pass) {
  if (!env || env.placeholder || !env.ct) return { placeholder: true };
  var subtle = globalThis.crypto.subtle, ck = env.salt + "|" + env.iter + "|" + pass;
  var key = keyCache[ck];
  if (!key) {
    var base = await subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
    key = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64(env.salt), iterations: env.iter },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    keyCache = {}; keyCache[ck] = key;
  }
  var pt = await subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv) }, key, b64(env.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ---------- Face ID / WebAuthn PRF ---------- */
function faceBlob() {
  try { return JSON.parse(localStorage.getItem(FACE_LS) || "null"); } catch (e) { return null; }
}
function clearFace() { localStorage.removeItem(FACE_LS); }
function clearPass() { localStorage.removeItem(KEY_LS); }
async function prfCapability() {
  if (!window.PublicKeyCredential) return "none";
  try {
    if (typeof PublicKeyCredential.getClientCapabilities === "function") {
      var caps = await PublicKeyCredential.getClientCapabilities();
      if (caps && caps["extension:prf"] === false) return "none";
      if (caps && caps["extension:prf"] === true) return "yes";
    }
  } catch (e) { /* fall through */ }
  return "unknown";
}
async function hkdfWrapKey(prfBytes) {
  var subtle = crypto.subtle;
  var ikm = await subtle.importKey("raw", prfBytes, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("ops-dashboard-wrap-v1") },
    ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
function prfFromResults(ext) {
  if (!ext || !ext.prf) return null;
  if (ext.prf.results && ext.prf.results.first) return ext.prf.results.first;
  return null;
}
async function obtainPrf(credId) {
  var assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname === "127.0.0.1" ? "localhost" : location.hostname,
      allowCredentials: [{ type: "public-key", id: credId }],
      userVerification: "required",
      timeout: 60000,
      extensions: { prf: { eval: { first: PRF_SALT } } }
    }
  });
  var ext = assertion.getClientExtensionResults();
  var out = prfFromResults(ext);
  if (!out) throw new Error((ext && ext.prf && ext.prf.enabled === false) ? "PRF not supported on this device" : "PRF unavailable on get");
  return out;
}
async function enableFaceId(passphrase) {
  var userId = crypto.getRandomValues(new Uint8Array(16));
  var cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: location.hostname === "127.0.0.1" ? "localhost" : location.hostname, name: "Bots" },
      user: { id: userId, name: "ops@" + location.hostname, displayName: "Bots" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "preferred",
        requireResidentKey: false
      },
      timeout: 90000,
      extensions: { prf: { eval: { first: PRF_SALT } } }
    }
  });
  if (!cred) throw new Error("cancelled");
  var ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
  var prfOut = prfFromResults(ext);
  if (!prfOut) {
    if (ext.prf && ext.prf.enabled === false) throw new Error("PRF not supported on this device");
    /* create often only reports enabled — get() yields the bytes */
    prfOut = await obtainPrf(cred.rawId);
  }
  var wrapKey = await hkdfWrapKey(prfOut);
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, wrapKey, new TextEncoder().encode(passphrase));
  localStorage.setItem(FACE_LS, JSON.stringify({
    v: 1, id: b64urlEnc(cred.rawId), iv: b64enc(iv), ct: b64enc(ct)
  }));
  clearPass();
  return true;
}
async function unlockWithFace() {
  var blob = faceBlob();
  if (!blob || !blob.id) throw new Error("no face blob");
  var prfOut = await obtainPrf(b64urlDec(blob.id));
  var wrapKey = await hkdfWrapKey(prfOut);
  var pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64(blob.iv) }, wrapKey, b64(blob.ct)
  );
  return new TextDecoder().decode(pt);
}

/* ---------- small helpers ---------- */
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
function hm(iso) { if (!iso) return "—"; return new Date(iso).toLocaleTimeString("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit" }); }
function ageMin(iso, now) { return Math.max(0, Math.round((now - Date.parse(iso)) / 60000)); }
function ago(m) { return m < 1 ? "now" : m < 60 ? m + "m ago" : m < 1440 ? Math.floor(m / 60) + "h " + (m % 60) + "m ago" : Math.floor(m / 1440) + "d ago"; }
function stampH(m) { return m > 60 ? "red" : m > 15 ? "warn" : "ok"; }
/* countdowns: computed at render time from UTC instants */
function cdTxt(iso, now) {
  var ms = Date.parse(iso) - now; if (isNaN(ms)) return "—";
  if (ms <= 0) return "due";
  var m = Math.floor(ms / 60000), d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60);
  return d ? d + "d " + h + "h" : h ? h + "h " + (m % 60) + "m" : m + "m";
}
function cdShort(iso, now) { var ms = Date.parse(iso) - now; return ms >= 3 * 864e5 ? Math.floor(ms / 864e5) + "d" : cdTxt(iso, now); }
function cdH(iso, now) { var ms = Date.parse(iso) - now; return ms < 864e5 ? "red" : ms < 3 * 864e5 ? "warn" : "idle"; }
function ukWhen(iso) { return new Date(iso).toLocaleString("en-GB", { timeZone: TZ, weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }); }
function usagePace(u, now) {
  var res = Date.parse(u.reset_utc || ""), upd = Date.parse(u.updated_utc || ""), W = 7 * 864e5;
  if (isNaN(res) || isNaN(upd) || u.pct == null) return { h: "idle", stale: true, frac: null, proj: null };
  var frac = Math.min(1, Math.max(0.02, (upd - (res - W)) / W));
  var nowFrac = Math.min(1, Math.max(0, (now - (res - W)) / W));
  var proj = u.pct / frac, stale = now - upd > 30 * 3600e3 || upd < res - W;
  var h = stale ? "warn" : (proj > 100 || u.pct >= 90) ? "red" : proj >= 80 ? "warn" : "ok";
  return { h: h, stale: stale, frac: frac, nowFrac: nowFrac, proj: proj };
}
function dots(days, big) {
  if (!days || !days.length) return "";
  return '<span class="days' + (big ? " big" : "") + '">' + days.map(function (h) { return '<i class="' + h + '"></i>'; }).join("") + "</span>";
}
function sym(h, s) {
  s = s || 12;
  var c = "var(--c)", w = "#fff";
  var inner = h === "ok" ? '<path d="M5.5 10.5l3 3 6-6.5" stroke="' + w + '" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
    : h === "red" ? '<path d="M6.5 6.5l7 7m0-7l-7 7" stroke="' + w + '" stroke-width="2.4" stroke-linecap="round"/>'
    : h === "idle" ? '<rect x="5.5" y="9" width="9" height="2.2" rx="1" fill="' + w + '"/>' : "";
  if (h === "warn") return '<svg class="warn" width="' + s + '" height="' + s + '" viewBox="0 0 20 20"><path d="M10 1.5L19 18H1z" fill="' + c + '"/><rect x="9" y="7" width="2" height="6" fill="' + w + '"/><rect x="9" y="14.3" width="2" height="2" fill="' + w + '"/></svg>';
  return '<svg class="' + h + '" width="' + s + '" height="' + s + '" viewBox="0 0 20 20"><circle cx="10" cy="10" r="9" fill="' + c + '"/>' + inner + "</svg>";
}
function failH(ids, failing, sev) {
  var bad = failing.filter(function (f) { return ids.indexOf(f) >= 0; });
  if (!bad.length) return "ok";
  return bad.some(function (f) { return sev[f] === "critical"; }) ? "red" : "warn";
}
function sevMap(v) { var m = {}; v.qa.checks.forEach(function (c) { m[c.id] = c.severity; }); return m; }
function depById(v, id) { return v.deps.filter(function (d) { return d.id === id; })[0]; }
function tileById(v, id) { return v.tiles.filter(function (t) { return t.id === id; })[0]; }

/* ---------- graphics ---------- */
function spark(prices, w, h) {
  if (!prices || prices.length < 2) return "";
  var ps = prices.map(function (p) { return p.p; }), mx = Math.max.apply(null, ps.concat([260])), mn = Math.min.apply(null, ps.concat([100]));
  var y = function (p) { return h - 2 - ((p - mn) / (mx - mn)) * (h - 4); };
  var pts = ps.map(function (p, i) { return (i / (ps.length - 1) * w).toFixed(1) + "," + y(p).toFixed(1); }).join(" ");
  var last = ps[ps.length - 1];
  return '<svg width="100%" height="' + h + '" viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none">' +
    '<line x1="0" x2="' + w + '" y1="' + y(200) + '" y2="' + y(200) + '" stroke="var(--tx3)" stroke-dasharray="3 3" stroke-width="1" vector-effect="non-scaling-stroke"/>' +
    '<polyline points="' + pts + '" fill="none" stroke="' + (last >= 200 ? "var(--red)" : "var(--ok)") + '" stroke-width="1.8" vector-effect="non-scaling-stroke" stroke-linejoin="round"/></svg>';
}
function gauge(price, size) {
  var max = 500, cx = 60, cy = 56, r = 44;
  function pt(v, rr) { var a = Math.PI * (1 - Math.min(Math.max(v, 0), max) / max); return [cx + rr * Math.cos(a), cy - rr * Math.sin(a)]; }
  function arc(a, b, col) { var p1 = pt(a, r), p2 = pt(b, r); return '<path d="M' + p1[0] + " " + p1[1] + " A" + r + " " + r + " 0 0 1 " + p2[0] + " " + p2[1] + '" stroke="' + col + '" stroke-width="11" fill="none"/>'; }
  var n = pt(price || 0, r - 12), col = price >= 200 ? "var(--red)" : "var(--ok)";
  return '<svg width="' + size + '" viewBox="0 0 120 78">' + arc(0, 150, "var(--ok)") + arc(150, 200, "var(--warn)") + arc(200, max, "var(--red)") +
    '<line x1="' + cx + '" y1="' + cy + '" x2="' + n[0] + '" y2="' + n[1] + '" stroke="var(--tx)" stroke-width="3.5" stroke-linecap="round"/><circle cx="' + cx + '" cy="' + cy + '" r="4.5" fill="var(--tx)"/>' +
    '<text x="60" y="76" text-anchor="middle" font-size="17" font-weight="800" fill="' + col + '">' + (price == null ? "—" : "£" + Math.round(price)) + "</text></svg>";
}
function ring(pct, h, size, label, mark) {
  var r = 40, C = 2 * Math.PI * r, len = Math.min(100, Math.max(0, pct || 0)) / 100 * C, mk = "";
  if (mark != null) { /* pace marker: where usage would be at an even pace (fraction of week elapsed) */
    var a = 2 * Math.PI * Math.min(1, Math.max(0, mark)) - Math.PI / 2;
    mk = '<line x1="' + (55 + 28 * Math.cos(a)).toFixed(1) + '" y1="' + (55 + 28 * Math.sin(a)).toFixed(1) + '" x2="' + (55 + 53 * Math.cos(a)).toFixed(1) + '" y2="' + (55 + 53 * Math.sin(a)).toFixed(1) + '" stroke="var(--tx)" stroke-width="7" stroke-linecap="round"/>';
  }
  return '<svg class="' + h + '" width="' + size + '" height="' + size + '" viewBox="0 0 110 110"><circle cx="55" cy="55" r="' + r + '" fill="none" stroke="var(--bd)" stroke-width="15"/>' +
    '<circle cx="55" cy="55" r="' + r + '" fill="none" stroke="var(--c)" stroke-width="15" stroke-linecap="round" stroke-dasharray="' + Math.max(len, 0.01) + " " + C + '" transform="rotate(-90 55 55)"/>' + mk +
    (label ? '<text x="55" y="63" text-anchor="middle" font-size="24" font-weight="800" fill="var(--tx)">' + esc(label) + "</text>" : "") + "</svg>";
}
var PALETTE = ["#3b82f6", "#a855f7", "#f59e0b", "#10b981", "#ef4444", "#06b6d4", "#84cc16", "#ec4899", "#64748b"];
function donut(parts, size) {
  var tot = parts.reduce(function (a, p) { return a + p[1]; }, 0) || 1, r = 40, C = 2 * Math.PI * r, off = 0, s = "";
  parts.forEach(function (p, i) { var l = p[1] / tot * C; s += '<circle cx="55" cy="55" r="' + r + '" fill="none" stroke="' + PALETTE[i % 9] + '" stroke-width="20" stroke-dasharray="' + l + " " + (C - l) + '" stroke-dashoffset="' + (-off) + '" transform="rotate(-90 55 55)"/>'; off += l; });
  return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 110 110">' + s + "</svg>";
}
function bars(rows, max) {
  return rows.map(function (r) { return '<div style="display:flex;align-items:center;gap:6px;font-size:11px;margin:2px 0"><span style="width:42px;color:var(--tx2)">' + esc(r[0]) + '</span><span style="flex:1;height:10px;background:var(--bd);border-radius:5px;overflow:hidden"><i style="display:block;height:100%;width:' + Math.min(100, r[1] / max * 100) + '%;background:' + (r[2] || "var(--ok)") + '"></i></span><b style="width:30px;text-align:right">' + esc(r[1]) + "</b></div>"; }).join("");
}
function dateBadge(d) {
  var dt = new Date(d + "T12:00:00Z");
  return '<span class="date"><b>' + dt.toLocaleDateString("en-GB", { weekday: "short", timeZone: TZ }).toUpperCase() + "</b><em>" + dt.getUTCDate() + "</em>" + dt.toLocaleDateString("en-GB", { month: "short", timeZone: TZ }) + "</span>";
}

/* ---------- layer 1: one-screen overview ---------- */
var OUTCOME_IDS = ["grid", "news", "lode", "yahoo", "planner", "dev", "tv", "car", "usage", "gate"];
var SUPPORT_IDS = ["tg", "wa", "qa", "dash"];
function tileHtml(v, t) {
  return '<button class="tile ' + t.h + '" data-go="t/' + t.id + '">' + (t.badge ? '<span class="b">' + esc(t.badge) + "</span>" : "") +
    '<span class="n">' + sym(t.h, 11) + esc(t.short) + '</span><span class="f' + (t.fig_h === "red" ? " red" : "") + '">' + esc(t.fig) + "</span>" +
    (t.spark === "price" ? spark(v.grid.prices, 100, 14) : t.spark === "qa" ? qaStrip(v, t.qa, 5) : "") + dots(t.days) +
    '<span class="keys">' + t.deps.map(function (d, i) { var dp = depById(v, d); return '<span class="key ' + t.dep_h[i] + '">' + esc(dp ? dp.key : "?") + "</span>"; }).join("") + "</span></button>";
}
function kpiStrip(v, now) {
  var c = v.counts || {}, g = v.grid || {}, u = v.usage || {}, nx = (v.upcoming || []).filter(function (x) { return !x.at_utc || Date.parse(x.at_utc) > now; })[0];
  var fc = v.forecast || {}, fw = fc.tomorrow || fc.tonight, pc = usagePace(u, now);
  var price = g.price, prices = g.prices || [], ps = prices.map(function (p) { return p.p; });
  var hi = ps.length ? Math.max.apply(null, ps) : null, lo = ps.length ? Math.min.apply(null, ps) : null;
  var ph = price != null && price > 200 ? "red" : "ok";
  var wa = depById(v, "whatsapp") || { h: "idle", fig: "—" };
  var waTile = tileById(v, "wa");
  var waFig = waTile ? waTile.fig : (wa.fig || "—");
  var waH = wa.h || (waTile ? waTile.h : "idle");
  var hh = (c.warn > 0 ? "warn" : c.red > 0 ? "red" : "ok");
  var nextLbl = nx ? (nx.at_utc ? cdTxt(nx.at_utc, now) : ((nx.date || "").slice(8) + " " + (nx.time || "")).trim()) : "—";
  var nextName = nx ? String(nx.label || "").split(" ")[0] : "";
  var nxH = nx && nx.at_utc ? cdH(nx.at_utc, now) : "idle";
  function cell(h, lab, body, go) {
    return '<button class="kpi ' + h + '"' + (go ? ' data-go="' + go + '"' : '') + '><span class="kl">' + lab + "</span>" + body + "</button>";
  }
  var o = '<div class="kpis">';
  o += cell(ph, "Grid £", '<span class="kf" style="color:var(--c)">£' + (price == null ? "—" : Math.round(price)) + "</span>" +
    (hi != null ? '<span class="ks">H ' + Math.round(hi) + " · L " + Math.round(lo) + "</span>" : "") +
    '<div style="width:100%">' + spark(prices, 100, 12) + "</div>" +
    (fw ? '<span class="ks fc">' + (fc.tomorrow ? "tmw" : "tngt") + ' <b class="' + (fw.hi > 200 ? "r" : "") + '">▲' + Math.round(fw.hi) + '</b> <b class="g">▼' + Math.round(fw.lo) + "</b></span>" : ""), "t/grid");
  o += cell(pc.h, "Usage %", '<span class="kf" style="color:var(--c)">' + ring(u.pct, pc.h, 22, "", pc.frac) + (u.pct == null ? "—" : u.pct + "%") + '</span><span class="ks">' + (pc.stale ? '<b style="color:var(--warn)">stale</b>' : "pace → " + Math.round(pc.proj) + "%") + "</span>", "usage");
  o += cell(waH, "WA link", '<span class="kf" style="color:var(--c)">' + sym(waH, 11) + " " + esc(waFig) + '</span><span class="ks">sync</span>', "t/wa");
  o += cell(hh, "Health", '<span class="kf"><span style="color:var(--ok)">' + (c.ok || 0) + '</span>·<span style="color:var(--warn)">' + (c.warn || 0) + '</span>·<span style="color:var(--red)">' + (c.red || 0) + '</span></span><span class="ks">g · a · r</span>', "");
  o += cell(nxH, "Next up", '<span class="kf"' + (nxH !== "idle" ? ' style="color:var(--c)"' : "") + ">" + esc(nextLbl || "—") + '</span><span class="ks">' + esc(nextName) + "</span>", "next");
  o += "</div>";
  return o;
}
function needsBanner(v) {
  var n = v.needs || [];
  if (!n.length) return "";
  return '<div class="needs">' + sym("red", 13) + n.map(function (x) {
    return x.bot_id ? '<a href="grokbot://app/v1/agent?id=' + esc(x.bot_id) + '">' + esc(x.label) + " ›</a>" : "<span>" + esc(x.label) + "</span>";
  }).join("") + "</div>";
}
function deadlineRow(v, now) {
  var d = (v.deadlines || []).filter(function (x) { return Date.parse(x.at_utc) > now - 864e5; });
  if (!d.length) return "";
  return '<button class="dl" data-go="deadlines"><span class="dli">⏳</span>' + d.slice(0, 3).map(function (x) {
    var h = cdH(x.at_utc, now);
    return '<span class="dlc ' + h + '"><i></i>' + esc(x.short || x.label) + " <b>" + (x.approx ? "~" : "") + esc(cdShort(x.at_utc, now)) + "</b></span>";
  }).join("") + (d.length > 3 ? '<span class="dlm">+' + (d.length - 3) + "</span>" : "") + "</button>";
}
function renderHome(v, now) {
  var c = v.counts, m = ageMin(v.as_of_utc, now), sh = stampH(m);
  var lamp = function (h, n) { return '<span class="lamp ' + h + (n ? " on" : "") + '">' + (n || "") + "</span>"; };
  var word = { ok: "All OK", warn: "Warnings", red: "Failures", idle: "Waiting" }[v.overall];
  var o = needsBanner(v) + '<div class="top"><span class="light">' + lamp("red", c.red) + lamp("warn", c.warn) + lamp("ok", c.ok) + lamp("idle", c.idle) + "</span>" +
    '<span class="headline ' + v.overall + '"><b>' + sym(v.overall, 13) + " " + word + '</b></span>' +
    '<span class="stamp ' + sh + '"><i></i>' + (sh === "ok" ? "" : "⚠ ") + ago(m) + "</span>" +
    '<button class="iconbtn" data-act="refresh" aria-label="Refresh">↻</button></div>';
  o += kpiStrip(v, now) + deadlineRow(v, now);
  var outs = v.tiles.filter(function (t) { return OUTCOME_IDS.indexOf(t.id) >= 0; });
  var sups = v.tiles.filter(function (t) { return SUPPORT_IDS.indexOf(t.id) >= 0; });
  var rest = v.tiles.filter(function (t) { return OUTCOME_IDS.indexOf(t.id) < 0 && SUPPORT_IDS.indexOf(t.id) < 0; });
  o += '<div class="lbl">Outcomes</div><div class="tiles">' + outs.map(function (t) { return tileHtml(v, t); }).join("") + "</div>";
  o += '<div class="lbl">Supporting</div><div class="tiles">' + sups.concat(rest).map(function (t) { return tileHtml(v, t); }).join("") + "</div>";
  o += '<div class="lbl">Dependencies</div><div class="chips">' + v.deps.map(function (d) {
    return '<button class="chip ' + d.h + '" data-go="d/' + d.id + '"><span class="key ' + d.h + '">' + esc(d.key) + "</span>" + esc(d.name) + " <small>" + esc(d.fig) + "</small></button>";
  }).join("") + "</div>";
  return o;
}
function qaStrip(v, ids, w) {
  var sev = sevMap(v), hist = v.qa.history.slice(-12);
  return '<svg width="100%" height="12" viewBox="0 0 ' + hist.length * w + ' 12" preserveAspectRatio="none">' + hist.map(function (r, i) {
    var h = failH(ids, r.failing, sev); return '<rect class="' + h + '" x="' + i * w + '" width="' + (w - 1) + '" height="12" rx="1" fill="var(--c)"/>';
  }).join("") + "</svg>";
}

/* ---------- layer 2: detail ---------- */
function kv(rows) { return '<div class="kv">' + rows.map(function (r) { return "<div><span>" + esc(r[0]) + "</span><span>" + esc(r[1]) + "</span></div>"; }).join("") + "</div>"; }
function hero(h, title, sub, big) { return '<div class="hero ' + h + '">' + sym(h, 30) + "<div><h1>" + esc(title) + '</h1><div class="s">' + esc(sub) + '</div></div><span class="big">' + esc(big || "") + "</span></div>"; }
function histStrip(v, ids) {
  var sev = sevMap(v), H = v.qa.history;
  if (!ids.length || !H.length) return "";
  return '<div class="lbl">QA history · ' + hm(H[0].t) + " → " + hm(H[H.length - 1].t) + '</div><div class="strip">' + H.map(function (r) { return '<i class="' + failH(ids, r.failing, sev) + '" title="' + esc(hm(r.t)) + '"></i>'; }).join("") + "</div>";
}
function qaChips(v, ids) {
  var by = {}; v.qa.checks.forEach(function (c) { by[c.id] = c; });
  var list = ids.filter(function (i) { return by[i]; });
  if (!list.length) return "";
  return '<div class="lbl">Checks</div><div class="qa">' + list.map(function (i) { var c = by[i], h = c.ok ? "ok" : c.severity === "critical" ? "red" : "warn"; return '<span class="chip ' + h + '">' + sym(h, 14) + esc(c.name) + "</span>"; }).join("") + "</div>";
}
function back() { return '<button class="back" data-act="back">‹ Back</button>'; }
function lastOutcomeBlock(t) {
  var lo = t.last_outcome;
  if (!lo || (!lo.when_utc && !lo.summary)) return "";
  var when = lo.when_utc ? hm(lo.when_utc) + " UK · " + new Date(lo.when_utc).toLocaleDateString("en-GB", { timeZone: TZ, weekday: "short", day: "numeric", month: "short" }) : "";
  return '<div class="lbl">Last outcome</div><div class="card outcome"><div class="when">' + esc(when) + '</div><div class="sum">' + esc(lo.summary || "") + "</div></div>";
}
function openBotBtn(t) {
  if (!t.bot_id) return "";
  return '<a class="grokbtn" href="grokbot://app/v1/agent?id=' + esc(t.bot_id) + '">Open in ' + esc(t.bot) + "</a>";
}
/* ---------- layer 3: last full output (lazy-loaded, same key) ---------- */
var OUTS = { data: null, imgs: {}, err: null, loading: false };
var JOB_NAMES = { "grid-alerts": "Grid alerts", "grid-forecast-telegram": "Grid forecast post", "grid-telegram-bot": "Telegram /status reply",
  "whatsapp-link": "WhatsApp link", "qa-health-checks": "Health checks", "ops-dashboard-publish": "Dashboard publish" };
function jobName(j) { return JOB_NAMES[j] || j.replace(/-/g, " ").replace(/^./, function (c) { return c.toUpperCase(); }); }
function md(s) {
  return esc(s).split("\n").map(function (l) {
    l = l.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>");
    if (/^#{1,3} /.test(l)) return "<b class=\"mdh\">" + l.replace(/^#{1,3} /, "") + "</b>";
    return l;
  }).join("\n");
}
function outBtn(t) { return t.outputs && t.outputs.length ? '<button class="grokbtn outbtn" data-go="o/' + esc(t.id) + '">▤ Full output</button>' : ""; }
function renderOutput(v, t, now) {
  var o = back();
  if (OUTS.err) return o + '<div class="card"><span class="cap">' + esc(OUTS.err) + "</span></div>";
  if (!OUTS.data) return o + '<div class="lock" style="margin-top:20vh">' + sym("idle", 32) + "</div>";
  var list = (t.outputs || []).map(function (j) { return OUTS.data[j]; }).filter(Boolean)
    .sort(function (a, b) { return (b.run_utc || "").localeCompare(a.run_utc || ""); });
  list.forEach(function (x) {
    var h = x.status || "idle", age = x.run_utc ? ago(ageMin(x.run_utc, now)) : "—";
    o += '<div class="l3h ' + h + '">' + sym(h, 14) + "<b>" + esc(jobName(x.job)) + '</b><span class="age">' + esc(age) + "</span></div>";
    o += '<div class="l3s">' + esc(x.summary || "") + "</div>";
    if (x.image_file) o += OUTS.imgs[x.job] ? '<img class="l3img" alt="" src="data:image/png;base64,' + OUTS.imgs[x.job] + '">' : '<div class="card"><span class="cap">image…</span></div>';
    o += '<div class="l3b">' + md(x.body || "") + "</div>";
    o += '<div class="l3f">' + esc(x.bot || "") + (x.run_utc ? " · " + esc(ukWhen(x.run_utc)) + " UK" : "") + (x.source ? " · " + esc(x.source) : "") + "</div>";
    if (x.history && x.history.length) o += "<details><summary>Earlier (" + x.history.length + ")</summary>" + x.history.map(function (hx) {
      return '<div class="l3hist"><span class="' + (hx.status || "idle") + '">' + sym(hx.status || "idle", 11) + "</span> " + esc(hx.run_utc ? ukWhen(hx.run_utc) : "") + " · " + esc(hx.summary || "") + "</div>";
    }).join("") + "</details>";
  });
  if (!list.length) o += '<div class="card"><span class="cap">No output stored yet</span></div>';
  return o;
}
function renderTile(v, t) {
  var o = back() + hero(t.h, t.name, t.bot, t.fig) + outBtn(t);
  if (OUTCOME_IDS.indexOf(t.id) >= 0) {
    o += lastOutcomeBlock(t);
    o += openBotBtn(t);
  }
  if (t.id === "grid") {
    var g = v.grid, sp = g.spell || {};
    o += '<div class="lbl">Price today (£/MWh, half-hourly)</div><div class="card">' + gauge(g.price, 170) + '<div style="width:100%">' + spark(g.prices, 300, 70) + "</div></div>";
    if (sp.since) o += '<div class="lbl">Above £200</div><div class="row3"><div class="card red"><b style="font-size:18px;color:var(--red)">£' + Math.round(sp.avg) + '</b><span class="cap">avg</span></div><div class="card"><b style="font-size:18px;color:var(--red)">£' + Math.round(sp.peak) + '</b><span class="cap">peak</span></div><div class="card"><b style="font-size:18px">' + hm(sp.since) + '</b><span class="cap">since · ' + sp.half_hours + " × ½h</span></div></div>";
    o += forecastBlock(v);
    if (g.mix && g.mix.nonren != null) o += '<div class="lbl">Mix</div><div class="card" style="align-items:stretch">' + bars([["Fossil", Math.round(g.mix.nonren), "var(--warn)"], ["Renew", Math.round(100 - g.mix.nonren - (g.mix.inter || 0)), "var(--ok)"], ["Import", Math.round(g.mix.inter || 0), "#3b82f6"]], 100) + "</div>";
  }
  if (t.id === "qa") o += '<div class="lbl">All checks</div>' + qaChips(v, t.qa).replace('<div class="lbl">Checks</div>', "");
  if (t.days && v.days) o += '<div class="lbl">Last 7 days</div><div class="week">' + t.days.map(function (h, i) { var d = new Date(v.days[i] + "T12:00:00Z"); return '<span class="' + h + '"><i></i>' + d.toLocaleDateString("en-GB", { weekday: "narrow", timeZone: TZ }) + "</span>"; }).join("") + "</div>";
  o += '<div class="lbl">Status</div>' + kv([["Last", t.last], ["Next", t.next], ["Schedule", t.schedule]].concat(t.outcome ? [["Outcome", t.outcome]] : []).concat(t.facts));
  o += histStrip(v, t.qa);
  if (t.id !== "qa") o += qaChips(v, t.qa);
  o += '<div class="lbl">Depends on</div><div class="chips">' + t.deps.map(function (d) { var dp = depById(v, d); return dp ? '<button class="chip ' + dp.h + '" data-go="d/' + dp.id + '"><span class="key ' + dp.h + '">' + esc(dp.key) + "</span>" + esc(dp.name) + "</button>" : ""; }).join("") + "</div>";
  o += '<div class="lbl">Open</div><div class="links">' + (t.bot_id ? '<a href="grokbot://app/v1/agent?id=' + esc(t.bot_id) + '">' + esc(t.bot) + "</a>" : "") + (t.link ? '<a href="' + esc(t.link[1]) + '">' + esc(t.link[0]) + "</a>" : "") + "</div>";
  return o;
}
function fcBars(pts) {
  if (!pts || !pts.length) return "";
  var mx = Math.max.apply(null, pts.map(function (p) { return p.p; }).concat([250])), w = 300, h = 60, bw = w / pts.length;
  return '<svg width="100%" height="' + (h + 12) + '" viewBox="0 0 ' + w + " " + (h + 12) + '" preserveAspectRatio="none">' + pts.map(function (p, i) {
    var bh = Math.max(2, p.p / mx * h), col = p.p > 200 ? "var(--red)" : p.p > 150 ? "var(--warn)" : "var(--ok)";
    var hr = new Date(p.t).toLocaleTimeString("en-GB", { timeZone: TZ, hour: "2-digit" });
    return '<rect x="' + (i * bw + 0.5).toFixed(1) + '" y="' + (h - bh).toFixed(1) + '" width="' + (bw - 1).toFixed(1) + '" height="' + bh.toFixed(1) + '" fill="' + col + '" rx="1"/>' +
      (i % 4 === 0 ? '<text x="' + (i * bw).toFixed(1) + '" y="' + (h + 10) + '" font-size="8" fill="var(--tx3)">' + hr + "</text>" : "");
  }).join("") + '<line x1="0" x2="' + w + '" y1="' + (h - 200 / mx * h).toFixed(1) + '" y2="' + (h - 200 / mx * h).toFixed(1) + '" stroke="var(--tx3)" stroke-dasharray="3 3"/></svg>';
}
function forecastBlock(v) {
  var f = v.forecast || {};
  if (!f.tonight && !f.tomorrow) return '<div class="lbl">Forecast</div><div class="card"><span class="cap">No day-ahead data yet</span></div>';
  function win(name, w) {
    if (!w) return '<div class="card idle"><span class="cap">' + name + '</span><b style="font-size:13px;color:var(--tx3)">not published</b><span class="cap">~11:00 UK</span></div>';
    return '<div class="card"><span class="cap">' + name + '</span><b style="font-size:17px;color:' + (w.hi > 200 ? "var(--red)" : "var(--tx)") + '">▲£' + Math.round(w.hi) + '</b><span class="cap">' + hm(w.hi_t) + '</span><b style="font-size:17px;color:var(--ok)">▼£' + Math.round(w.lo) + '</b><span class="cap">' + hm(w.lo_t) + "</span></div>";
  }
  return '<div class="lbl">Day-ahead forecast (£/MWh)</div><div class="row3" style="grid-template-columns:1fr 1fr">' + win("Tonight → 07:00", f.tonight) + win("Tomorrow 07–24", f.tomorrow) + "</div>" +
    '<div class="lbl">Cheapest hours</div><div class="chips">' + (f.cheapest || []).map(function (p) { return '<span class="chip ok"><span class="key ok">£</span>' + hm(p.t) + " <small>£" + Math.round(p.p) + "</small></span>"; }).join("") + "</div>" +
    '<div class="card" style="margin-top:5px;align-items:stretch">' + fcBars(f.points) + '<span class="cap">' + esc(f.source || "") + "</span></div>";
}
function renderDep(v, d) {
  var users = v.tiles.filter(function (t) { return t.deps.indexOf(d.id) >= 0; });
  return back() + hero(d.h, d.name, "Supports " + users.length, d.fig) + '<div class="lbl">Status</div>' + kv(d.facts) + histStrip(v, d.qa) + qaChips(v, d.qa) +
    '<div class="lbl">Supports</div><div class="tiles">' + users.map(function (t) { return '<button class="tile ' + t.h + '" data-go="t/' + t.id + '"><span class="n">' + sym(t.h, 11) + esc(t.short) + '</span><span class="f">' + esc(t.fig) + "</span></button>"; }).join("") + "</div>";
}
function renderUsage(v, now) {
  var pc = usagePace(v.usage, now || Date.now());
  var u = v.usage, tot = u.by_bot.reduce(function (a, b) { return a + b[1]; }, 0) || 1;
  var reset = u.reset_utc ? new Date(u.reset_utc).toLocaleString("en-GB", { timeZone: TZ, weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "—";
  var o = back() + hero(pc.h, "Usage", "Resets " + reset + " UK", u.pct == null ? "—" : u.pct + "%");
  o += '<div class="row3" style="grid-template-columns:1fr 1fr"><div class="card ' + pc.h + '">' + ring(u.pct, pc.h, 120, Math.round(u.pct || 0) + "%", pc.frac) + '<span class="cap">' + (pc.stale ? '<b style="color:var(--warn)">stale reading</b>' : "▮ = even pace") + '</span></div><div class="card">' + donut(u.by_bot, 120) + '<span class="cap">share by bot</span></div></div>';
  o += '<div class="lbl">By bot (% of this week)</div><div class="chips">' + u.by_bot.map(function (b, i) { return '<span class="chip idle"><span class="key" style="background:' + PALETTE[i % 9] + '"></span>' + esc(b[0]) + " <small>" + Math.round(b[1] / tot * 100) + "%</small></span>"; }).join("") + "</div>";
  if (u.daily.length) { var mx = Math.max.apply(null, u.daily.map(function (d) { return d[1]; })); o += '<div class="lbl">Daily (% of limit)</div><div class="card" style="align-items:stretch">' + bars(u.daily.slice(-10).map(function (d) { return [d[0], d[1], d[1] > 12 ? "var(--warn)" : "var(--ok)"]; }), mx) + "</div>"; }
  o += '<div class="lbl">Pace</div>' + kv([["Week elapsed at reading", pc.frac == null ? "—" : Math.round(pc.frac * 100) + "%"], ["Projected at reset", pc.proj == null ? "—" : Math.round(pc.proj) + "%"], ["Reading", pc.stale ? "Stale (over 30h old)" : "Fresh"]]);
  o += '<div class="lbl">Source</div>' + kv([["Last read", u.updated_utc ? hm(u.updated_utc) + " UK · " + new Date(u.updated_utc).toLocaleDateString("en-GB", { timeZone: TZ, day: "numeric", month: "short" }) : "—"]]);
  return o;
}
function cdRow(n, now, link) {
  var h = n.at_utc ? cdH(n.at_utc, now) : "idle";
  return '<div style="align-items:center"' + (link || "") + ">" + dateBadge(n.date) + '<span style="flex:1;color:var(--tx);font-weight:600;text-align:left">' + esc(n.label) +
    '<small style="display:block;color:var(--tx3);font-weight:500">' + esc((n.time || "all day") + (n.approx ? " · approx" : "")) + "</small></span>" +
    '<span class="cd ' + h + '">' + (n.approx ? "~" : "") + esc(n.at_utc ? cdTxt(n.at_utc, now) : "") + "</span></div>";
}
function renderDeadlines(v, now) {
  var d = v.deadlines || [];
  return back() + hero(d.length && cdH(d[0].at_utc, now) !== "idle" ? cdH(d[0].at_utc, now) : "idle", "Renewals & deadlines", d.length + " items", "") +
    '<div class="lbl">Due</div><div class="kv">' + d.map(function (n) { return cdRow(n, now, ""); }).join("") + "</div>" + openGrok();
}
function openGrok() { return '<div class="lbl">Open</div><div class="links"><a href="grokbot://app/v1/agent?id=0e4bea7e-6330-4006-8676-5fa68a214570">Grok Bot</a></div>'; }
function renderNext(v, now) {
  now = now || Date.now();
  var items = (v.upcoming || []).concat(v.deadlines || []).filter(function (x) { return !x.at_utc || Date.parse(x.at_utc) > now; })
    .sort(function (a, b) { return (a.at_utc || a.date).localeCompare(b.at_utc || b.date); });
  return back() + hero("idle", "Coming up", items.length + " items", "") + '<div class="lbl">Next</div><div class="kv">' + items.map(function (n) {
    var link = n.proc && tileById(v, n.proc) ? ' data-go="t/' + n.proc + '"' : "";
    return cdRow(n, now, link);
  }).join("") + '</div><div class="lbl">Open</div><div class="links"><a href="' + esc(v.routines_href) + '">Routines</a></div>';
}
function renderRoute(route, v, now) {
  var p = (route || "").replace(/^#/, "");
  if (p.indexOf("t/") === 0 && tileById(v, p.slice(2))) return renderTile(v, tileById(v, p.slice(2)));
  if (p.indexOf("o/") === 0 && tileById(v, p.slice(2))) return renderOutput(v, tileById(v, p.slice(2)), now);
  if (p.indexOf("d/") === 0 && depById(v, p.slice(2))) return renderDep(v, depById(v, p.slice(2)));
  if (p === "usage") return renderUsage(v, now);
  if (p === "next") return renderNext(v, now);
  if (p === "deadlines") return renderDeadlines(v, now);
  return renderHome(v, now);
}
function renderLock(msg, opts) {
  opts = opts || {};
  var face = !!opts.face;
  var note = opts.note || "";
  var o = '<div class="lock"><svg width="56" height="56" viewBox="0 0 20 20"><rect x="7" y="1" width="6" height="18" rx="2.5" fill="#262a32"/><circle cx="10" cy="5" r="2" fill="#f05252"/><circle cx="10" cy="10" r="2" fill="#f2a91d"/><circle cx="10" cy="15" r="2" fill="#34c472"/></svg>';
  if (face) o += '<button class="go face" type="button" data-act="face">Unlock with Face ID</button><div class="or">or passphrase</div>';
  o += '<form id="lockf" style="display:contents"><input id="pw" type="password" autocomplete="current-password" placeholder="Passphrase" aria-label="Passphrase">' +
    '<button class="go" type="submit">Unlock</button></form>';
  if (note) o += '<div class="note">' + esc(note) + "</div>";
  o += '<div class="err">' + esc(msg || "") + "</div></div>";
  return o;
}
function footerBar(hasFace, showEnable) {
  var bits = [];
  if (showEnable) bits.push('<button data-act="enable-face" class="footbtn">Use Face ID</button>');
  if (hasFace) bits.push('<span class="footok">Face ID on</span>');
  bits.push('<button data-act="forget" class="footbtn muted">Forget on this device</button>');
  return '<a class="grokbtn" href="grokbot://app/v1/agent?id=0e4bea7e-6330-4006-8676-5fa68a214570">Open Grok Bot</a><div class="foot">' + bits.join("") + "</div>";
}

if (typeof module !== "undefined") module.exports = { decryptEnvelope: decryptEnvelope, renderHome: renderHome, renderRoute: renderRoute, enableFaceId: enableFaceId, unlockWithFace: unlockWithFace, hkdfWrapKey: hkdfWrapKey, PRF_SALT: PRF_SALT, FACE_LS: FACE_LS, KEY_LS: KEY_LS };

/* ---------- browser glue ---------- */
if (typeof document !== "undefined") (function () {
  var app = document.getElementById("app"), data = null, busy = false, stack = [];
  var sessionPass = null; /* in-memory only; never written when Face ID is on */

  function draw() {
    if (!data) return;
    if (data.placeholder) {
      app.innerHTML = '<div class="lock">' + sym("idle", 48) + '<div class="err" style="color:var(--tx2)">No data published yet</div><button class="iconbtn" data-act="forget">⏏</button></div>';
      return;
    }
    var r = location.hash || "";
    if (/^#o\//.test(r)) ensureOutputs(r.slice(3));
    var showEnable = !faceBlob() && !!sessionPass;
    app.innerHTML = renderRoute(r, data, Date.now()) + (r ? "" : footerBar(!!faceBlob(), showEnable));
  }

  async function ensureOutputs(tid) {
    var t = tileById(data, tid); if (!t) return;
    if (!OUTS.data && !OUTS.loading && sessionPass) {
      OUTS.loading = true;
      try {
        var res = await fetch("outputs.enc.json?t=" + Date.now(), { cache: "no-store" });
        if (!res.ok) throw new Error("http " + res.status);
        OUTS.data = (await decryptEnvelope(await res.json(), sessionPass)).outputs || {}; OUTS.err = null;
      } catch (e) { OUTS.err = "Couldn't load outputs"; }
      OUTS.loading = false; draw(); return;
    }
    if (!OUTS.data) return;
    (t.outputs || []).forEach(async function (j) {
      var x = OUTS.data[j]; if (!x || !x.image_file || OUTS.imgs[j] || OUTS.imgs[j] === "") return;
      OUTS.imgs[j] = "";
      try {
        var r2 = await fetch(x.image_file + "?t=" + Date.now(), { cache: "no-store" });
        OUTS.imgs[j] = (await decryptEnvelope(await r2.json(), sessionPass)).b64; draw();
      } catch (e) { delete OUTS.imgs[j]; }
    });
  }
  async function load(pass) {
    if (busy) return; busy = true;
    try {
      var res = await fetch("data.enc.json?t=" + Date.now(), { cache: "no-store" });
      if (!res.ok) throw new Error("http " + res.status);
      var env = await res.json();
      try { data = await decryptEnvelope(env, pass); }
      catch (e) {
        if (!faceBlob()) clearPass();
        sessionPass = null;
        app.innerHTML = renderLock("Wrong passphrase", { face: !!faceBlob() });
        bindLock();
        return;
      }
      sessionPass = pass;
      if (!/^#o\//.test(location.hash)) { OUTS.data = null; OUTS.imgs = {}; OUTS.err = null; }
      /* Keep plaintext passphrase only when Face ID is not configured. */
      if (!faceBlob()) localStorage.setItem(KEY_LS, pass);
      else clearPass();
      draw();
    } catch (e) {
      if (!data) {
        app.innerHTML = renderLock("Can't reach data, retrying", { face: !!faceBlob() });
        bindLock();
      }
    } finally { busy = false; }
  }

  function bindLock() {
    var f = document.getElementById("lockf");
    if (f) f.onsubmit = function (e) {
      e.preventDefault();
      var p = document.getElementById("pw").value;
      if (p) { app.innerHTML = '<div class="lock">' + sym("idle", 40) + "</div>"; load(p); }
    };
  }

  async function tryFaceThenFallback(msg) {
    var blob = faceBlob();
    if (!blob) {
      app.innerHTML = renderLock(msg || "");
      bindLock();
      return;
    }
    app.innerHTML = '<div class="lock">' + sym("idle", 40) + '<div class="note">Face ID…</div></div>';
    try {
      var pass = await unlockWithFace();
      await load(pass);
    } catch (e) {
      var name = (e && e.name) || "";
      var cancelled = name === "NotAllowedError" || /cancel/i.test(String(e && e.message));
      app.innerHTML = renderLock(cancelled ? "" : "Face ID failed — use passphrase", { face: true });
      bindLock();
    }
  }

  async function onEnableFace() {
    if (!sessionPass) return;
    var cap = await prfCapability();
    if (cap === "none") {
      draw();
      var foot = app.querySelector(".foot");
      if (foot) {
        var n = document.createElement("div");
        n.className = "note";
        n.textContent = "Face ID needs iOS 18+ Safari (passkey PRF). Passphrase stays remembered.";
        foot.prepend(n);
      }
      return;
    }
    try {
      app.innerHTML = '<div class="lock">' + sym("idle", 40) + '<div class="note">Confirm Face ID…</div></div>';
      await enableFaceId(sessionPass);
      draw();
    } catch (e) {
      var msg = (e && e.message) || "Face ID setup failed";
      if (/PRF not supported/i.test(msg) || (e && e.name === "NotSupportedError")) {
        if (!faceBlob()) localStorage.setItem(KEY_LS, sessionPass);
        draw();
        var foot2 = app.querySelector(".foot");
        if (foot2) {
          var n2 = document.createElement("div");
          n2.className = "note";
          n2.textContent = "This device has no passkey PRF (need iOS 18+). Passphrase stays remembered.";
          foot2.prepend(n2);
        }
        return;
      }
      draw();
    }
  }

  function doForget() {
    clearPass();
    clearFace();
    sessionPass = null;
    data = null;
    keyCache = {};
    location.hash = "";
    app.innerHTML = renderLock("");
    bindLock();
  }

  app.addEventListener("click", function (e) {
    var el = e.target.closest("[data-go],[data-act]"); if (!el) return;
    if (el.dataset.go) { stack.push(location.hash.replace("#", "")); location.hash = el.dataset.go; return; }
    var a = el.dataset.act;
    if (a === "back") { var prev = stack.pop() || ""; if (location.hash.replace("#", "") === prev) prev = ""; location.hash = prev; }
    if (a === "refresh") {
      var p = sessionPass || (!faceBlob() && localStorage.getItem(KEY_LS));
      if (p) load(p);
      else if (faceBlob()) tryFaceThenFallback();
    }
    if (a === "forget") doForget();
    if (a === "enable-face") onEnableFace();
    if (a === "face") tryFaceThenFallback();
  });

  window.addEventListener("hashchange", function () { draw(); window.scrollTo(0, 0); });

  (async function boot() {
    if (faceBlob()) {
      await tryFaceThenFallback();
      return;
    }
    var saved = localStorage.getItem(KEY_LS);
    if (saved) load(saved);
    else { app.innerHTML = renderLock(""); bindLock(); }
  })();

  setInterval(function () {
    if (document.hidden) return;
    var p = sessionPass || (!faceBlob() && localStorage.getItem(KEY_LS));
    if (p) load(p);
  }, REFRESH_MS);
  setInterval(function () { if (data && (!location.hash || /^#(next|deadlines|usage)$/.test(location.hash))) draw(); }, 20000);
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    var p = sessionPass || (!faceBlob() && localStorage.getItem(KEY_LS));
    if (p) load(p);
  });
})();
