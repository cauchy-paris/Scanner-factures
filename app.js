"use strict";
/* Scanner de factures : prise de vue, cadrage, envoi vers OneDrive (Microsoft Graph) */

/* ---------- Configuration ---------- */
const CFG = window.SCANNER_CONFIG || {};
const CLIENT_ID = CFG.clientId || "";
const AUTHORITY = "https://login.microsoftonline.com/" + (CFG.tenant || "common");
const SCOPES = "openid profile offline_access User.Read Files.ReadWrite";
const REDIRECT_URI = location.origin + location.pathname.replace(/index\.html$/, "");
const GRAPH = "https://graph.microsoft.com/v1.0";
const DEFAULT_PATH = Array.isArray(CFG.defaultPath) ? CFG.defaultPath : [];
const AUTO_FOLDER_NOTE = CFG.autoFolderNote || "";
const MAX_UPLOAD = 250 * 1024 * 1024;
const PHOTO_TARGET = 2500000;        // poids visé pour une photo (octets)
const MAX_SRC = 3600;                // côté max de l'image source traitée
const MAX_OUT = 3000;                // côté max du document recadré

const $ = id => document.getElementById(id);
const store = {
  get(k, d){ try{ const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; }catch(e){ return d; } },
  set(k, v){ try{ localStorage.setItem(k, JSON.stringify(v)); }catch(e){} },
  del(k){ try{ localStorage.removeItem(k); }catch(e){} }
};

/* ---------- État ---------- */
let dest = null;            // [{name, id}] du dossier racine au dossier choisi
let items = [];
let seq = 0;
let sending = false;
const opt = { pdf: store.get("scanner.pdf.v2", false), bw: store.get("scanner.bw", false) };
$("optPdf").checked = opt.pdf; $("optBw").checked = opt.bw;
$("optPdf").onchange = e => { opt.pdf = e.target.checked; store.set("scanner.pdf.v2", opt.pdf); refreshNames(); };
$("optBw").onchange = e => { opt.bw = e.target.checked; store.set("scanner.bw", opt.bw); };

function showBanner(text, isErr){ const b = $("banner"); b.textContent = text; b.className = "banner" + (isErr ? " err" : ""); b.hidden = !text; }

/* ---------- Connexion Microsoft (OAuth 2.0, code + PKCE) ---------- */
const auth = {
  tok: store.get("scanner.tok", null),   // {access, refresh, exp}
  user: store.get("scanner.user", null), // {name, mail, id}
  get signedIn(){ return !!(this.tok && this.tok.refresh); }
};
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function randStr(n){ const a = new Uint8Array(n); crypto.getRandomValues(a); return b64url(a); }

async function signIn(silent){
  if (!CLIENT_ID) { showBanner("Identifiant d'application Microsoft manquant dans config.js.", true); return; }
  const verifier = randStr(48), state = randStr(16);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  sessionStorage.setItem("scanner.pkce", JSON.stringify({verifier, state, silent: !!silent}));
  const p = new URLSearchParams({ client_id: CLIENT_ID, response_type: "code", redirect_uri: REDIRECT_URI, response_mode: "query",
    scope: SCOPES, state, code_challenge: challenge, code_challenge_method: "S256" });
  if (silent) { p.set("prompt", "none"); if (auth.user && auth.user.mail) p.set("login_hint", auth.user.mail); }
  else p.set("prompt", "select_account");
  location.assign(AUTHORITY + "/oauth2/v2.0/authorize?" + p);
}
function signOut(){
  store.del("scanner.tok"); store.del("scanner.user"); auth.tok = null; auth.user = null; dest = null;
  location.assign(AUTHORITY + "/oauth2/v2.0/logout?post_logout_redirect_uri=" + encodeURIComponent(REDIRECT_URI));
}
async function tokenRequest(params){
  const r = await fetch(AUTHORITY + "/oauth2/v2.0/token", { method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: new URLSearchParams(Object.assign({client_id: CLIENT_ID, scope: SCOPES}, params)) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.error_description || j.error || ("HTTP " + r.status)); e.code = j.error; throw e; }
  auth.tok = { access: j.access_token, refresh: j.refresh_token || (auth.tok && auth.tok.refresh), exp: Date.now() + (j.expires_in || 3600) * 1000 };
  store.set("scanner.tok", auth.tok);
  return auth.tok.access;
}
async function handleRedirect(){
  const q = new URLSearchParams(location.search);
  if (!q.has("code") && !q.has("error")) return false;
  const saved = JSON.parse(sessionStorage.getItem("scanner.pkce") || "null");
  sessionStorage.removeItem("scanner.pkce");
  history.replaceState(null, "", REDIRECT_URI);
  if (q.has("error")) {
    if (saved && saved.silent) return false;   // la connexion silencieuse a échoué : on affichera le bouton
    showBanner("Connexion refusée : " + (q.get("error_description") || q.get("error")), true); return false;
  }
  if (!saved || saved.state !== q.get("state")) { showBanner("La connexion a expiré. Réessayez.", true); return false; }
  await tokenRequest({ grant_type: "authorization_code", code: q.get("code"), redirect_uri: REDIRECT_URI, code_verifier: saved.verifier });
  return true;
}
let refreshing = null;
async function getToken(){
  if (!auth.tok) throw Object.assign(new Error("Non connecté"), {code: "signed_out"});
  if (auth.tok.access && auth.tok.exp > Date.now() + 90000) return auth.tok.access;
  if (!refreshing) refreshing = tokenRequest({ grant_type: "refresh_token", refresh_token: auth.tok.refresh })
    .catch(e => { store.del("scanner.tok"); auth.tok = null; throw Object.assign(new Error("Session expirée"), {code: "signed_out"}); })
    .finally(() => { refreshing = null; });
  return refreshing;
}
async function graph(path, opts = {}){
  const token = await getToken();
  const r = await fetch(path.startsWith("http") ? path : GRAPH + path, Object.assign({}, opts, {
    headers: Object.assign({Authorization: "Bearer " + token}, opts.json ? {"Content-Type": "application/json"} : {}, opts.headers || {}),
    body: opts.json ? JSON.stringify(opts.json) : opts.body }));
  if (r.status === 204) return null;
  const j = await r.json().catch(() => null);
  if (!r.ok) { const e = new Error((j && j.error && j.error.message) || ("HTTP " + r.status)); e.status = r.status; e.code = j && j.error && j.error.code; throw e; }
  return j;
}
function errText(e){
  if (!e) return "Erreur inconnue.";
  if (e.code === "signed_out") return "Votre session Microsoft a expiré. Reconnectez-vous puis renvoyez.";
  if (e.status === 403) return "OneDrive refuse l'accès à ce dossier (droits insuffisants).";
  if (e.status === 404) return "Dossier introuvable : il a peut-être été déplacé ou supprimé. Choisissez-en un autre.";
  if (e.status === 429 || e.status === 503) return "OneDrive est surchargé pour l'instant. Réessayez dans une minute.";
  if (e instanceof TypeError) return "Pas de connexion Internet, ou OneDrive injoignable.";
  return "Erreur OneDrive : " + String(e.message || e).slice(0, 220);
}

/* ---------- Démarrage ---------- */
async function boot(){
  try { await handleRedirect(); } catch(e) { showBanner("Connexion impossible : " + e.message, true); }
  if (auth.tok) {
    try { await getToken(); }
    catch(e) {
      // jeton de rafraîchissement expiré (24 h) : reconnexion silencieuse, une fois par session
      if (auth.user && !sessionStorage.getItem("scanner.silentTried")) { sessionStorage.setItem("scanner.silentTried", "1"); return signIn(true); }
    }
  }
  if (auth.signedIn) {
    try {
      if (!auth.user) { const me = await graph("/me?$select=id,displayName,mail,userPrincipalName");
        auth.user = {id: me.id, name: me.displayName, mail: me.mail || me.userPrincipalName}; store.set("scanner.user", auth.user); }
      sessionStorage.removeItem("scanner.silentTried");
      await initDest();
      refreshTracking();
    } catch(e) { showBanner(errText(e), true); }
  }
  render();
}

/* ---------- Destination ---------- */
function destKey(){ return "scanner.dest." + (auth.user ? auth.user.id : ""); }
async function initDest(){
  const saved = store.get(destKey(), null);
  if (Array.isArray(saved) && saved.length) { dest = saved; return; }
  const root = await graph("/me/drive/root?$select=id");
  let stack = [{name: "OneDrive", id: root.id}];
  try {
    for (let i = 0; i < DEFAULT_PATH.length; i++) {
      const p = DEFAULT_PATH.slice(0, i + 1).map(encodeURIComponent).join("/");
      const it = await graph("/me/drive/root:/" + p + "?$select=id,name,folder");
      if (!it.folder) break;
      stack.push({name: it.name, id: it.id});
    }
  } catch(e) { /* chemin par défaut absent : on garde ce qui a été trouvé */ }
  dest = stack;
}
function renderDest(){
  const p = $("destPath"); p.textContent = "";
  if (!dest) { p.textContent = auth.signedIn ? "Chargement…" : "Connectez-vous pour choisir un dossier"; $("destHint").textContent = ""; return; }
  dest.forEach((d, i) => {
    if (i) p.append(" / ");
    if (i === dest.length - 1) { const b = document.createElement("b"); b.textContent = d.name; p.append(b); } else p.append(d.name);
  });
  const last = dest[dest.length - 1].name, full = dest.slice(1).map(d => d.name).join("/");
  $("destHint").textContent = AUTO_FOLDER_NOTE && DEFAULT_PATH.length && full === DEFAULT_PATH.join("/") ? AUTO_FOLDER_NOTE : "";
}
function renderAccount(){
  const a = $("account");
  a.hidden = false;
  $("accName").textContent = auth.signedIn && auth.user ? (auth.user.mail || auth.user.name) : "";
  $("signInBtn").hidden = auth.signedIn; $("signOutBtn").hidden = !auth.signedIn;
  $("chooseDest").disabled = !auth.signedIn;
}
$("signInBtn").onclick = () => signIn(false);
$("signOutBtn").onclick = signOut;

/* ---------- Sélecteur de dossier ---------- */
let fmStack = [];
function openFolderModal(){
  if (!auth.signedIn || !dest) return;
  fmStack = dest.slice();
  $("folderModal").hidden = false;
  $("newfRow").hidden = true; $("newfBtn").hidden = false;
  loadFolder();
}
function closeFolderModal(){ $("folderModal").hidden = true; }
$("chooseDest").onclick = openFolderModal;
$("fmClose").onclick = closeFolderModal;
$("folderModal").addEventListener("click", e => { if (e.target.id === "folderModal") closeFolderModal(); });
$("fmPick").onclick = () => { dest = fmStack.slice(); store.set(destKey(), dest); closeFolderModal(); render(); };

function renderCrumbs(){
  const c = $("fmCrumbs"); c.textContent = "";
  fmStack.forEach((d, i) => {
    if (i) { const s = document.createElement("i"); s.textContent = "/"; c.append(s); }
    const b = document.createElement("button"); b.type = "button"; b.textContent = d.name;
    if (i === fmStack.length - 1) b.setAttribute("aria-current", "page");
    b.onclick = () => { fmStack = fmStack.slice(0, i + 1); loadFolder(); };
    c.append(b);
  });
}
async function loadFolder(){
  renderCrumbs();
  const list = $("fmList"), cur = fmStack[fmStack.length - 1];
  list.innerHTML = '<div class="fstate">Chargement des dossiers…</div>';
  try {
    let url = "/me/drive/items/" + cur.id + "/children?$select=id,name,folder&$top=200", folders = [];
    while (url) { const j = await graph(url); folders.push(...j.value.filter(x => x.folder)); url = j["@odata.nextLink"]; }
    if (fmStack[fmStack.length - 1] !== cur) return;
    folders.sort((a, b) => a.name.localeCompare(b.name, "fr"));
    list.textContent = "";
    if (!folders.length) { list.innerHTML = '<div class="fstate">Aucun sous-dossier. Vous pouvez envoyer ici ou créer un dossier.</div>'; return; }
    for (const f of folders) {
      const b = document.createElement("button"); b.type = "button"; b.className = "frow";
      b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg><span></span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" style="color:var(--muted)"><path d="m9 6 6 6-6 6"/></svg>';
      b.querySelector("span").textContent = f.name;
      b.onclick = () => { fmStack.push({name: f.name, id: f.id}); loadFolder(); };
      list.append(b);
    }
  } catch(e) {
    list.textContent = ""; const d = document.createElement("div"); d.className = "fstate"; d.textContent = errText(e); list.append(d);
  }
}
$("newfBtn").onclick = () => { $("newfRow").hidden = false; $("newfBtn").hidden = true; $("newfName").value = ""; $("newfName").focus(); };
$("newfCancel").onclick = () => { $("newfRow").hidden = true; $("newfBtn").hidden = false; };
$("newfName").addEventListener("keydown", e => { if (e.key === "Enter") $("newfOk").click(); });
$("newfOk").onclick = async () => {
  const name = $("newfName").value.trim().replace(/[\\/:*?"<>|]/g, "-");
  if (!name) return;
  const cur = fmStack[fmStack.length - 1];
  $("newfOk").disabled = true;
  try {
    const f = await graph("/me/drive/items/" + cur.id + "/children", { method: "POST", json: {name, folder: {}, "@microsoft.graph.conflictBehavior": "rename"} });
    $("newfRow").hidden = true; $("newfBtn").hidden = false;
    fmStack.push({name: f.name, id: f.id}); loadFolder();
  } catch(e) {
    const d = document.createElement("div"); d.className = "fstate"; d.style.color = "var(--err)"; d.textContent = errText(e); $("fmList").prepend(d);
  } finally { $("newfOk").disabled = false; }
};

/* ---------- Ajout de fichiers ---------- */
$("camInput").onchange = e => { addFiles(e.target.files, true); e.target.value = ""; };
$("fileInput").onchange = e => { addFiles(e.target.files, false); e.target.value = ""; };
$("drop").onclick = () => $("fileInput").click();
let dragDepth = 0;
window.addEventListener("dragenter", e => { if (hasFiles(e)) { e.preventDefault(); dragDepth++; $("dropcover").hidden = false; $("drop").classList.add("on"); } });
window.addEventListener("dragover", e => { if (hasFiles(e)) e.preventDefault(); });
window.addEventListener("dragleave", e => { if (hasFiles(e) && --dragDepth <= 0) { dragDepth = 0; $("dropcover").hidden = true; $("drop").classList.remove("on"); } });
window.addEventListener("drop", e => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth = 0; $("dropcover").hidden = true; $("drop").classList.remove("on"); addFiles(e.dataTransfer.files, false); });
window.addEventListener("paste", e => { const f = [...(e.clipboardData?.files || [])]; if (f.length) addFiles(f, false); });
function hasFiles(e){ return e.dataTransfer && [...e.dataTransfer.types].includes("Files"); }

function stamp(d){ const p = n => String(n).padStart(2, "0"); return d.getFullYear() + p(d.getMonth()+1) + p(d.getDate()) + "_" + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds()); }
function baseName(n){ return n.replace(/\.[^.]+$/, "").replace(/[\\/:*?"<>|#%]/g, "-").trim() || "document"; }

function addFiles(list, fromCamera){
  const files = [...(list || [])];
  let skipped = 0;
  for (const f of files) {
    const isPdf = f.type === "application/pdf" || /\.pdf$/i.test(f.name);
    const isImg = !isPdf && (f.type.startsWith("image/") || /\.(jpe?g|png|heic|heif|webp|gif|bmp)$/i.test(f.name));
    if (!isPdf && !isImg) { skipped++; continue; }
    const now = new Date();
    const it = { id: ++seq, file: f, kind: isPdf ? "pdf" : "image", status: "queued", msg: "", out: null, outType: "", thumb: "",
      corners: null, auto: null, rot: 0, bw: opt.bw, w: 0, h: 0, review: !!fromCamera && isImg,
      base: fromCamera || (isImg && /^(image|photo)\.\w+$|^IMG|^PXL_|^\d{8}_\d{6}/i.test(f.name)) ? "Scan_" + stamp(now) : baseName(f.name) };
    items.push(it);
  }
  if (skipped) showBanner(skipped + " fichier(s) ignoré(s) : seuls les photos et les PDF sont acceptés.", false);
  render();
  pump();
}

let pumping = false;
async function pump(){
  if (pumping) return; pumping = true;
  try {
    let it;
    while ((it = items.find(x => x.status === "queued"))) {
      it.status = "processing"; render();
      try { await prepare(it); it.status = it.msg && it.tooBig ? "error" : "ready"; }
      catch(e) { it.status = "error"; it.msg = "Lecture impossible : " + (e && e.message || e); }
      render();
      if (it.review && it.status === "ready" && !ed) { it.review = false; await openEditor(it); }
    }
  } finally { pumping = false; }
}

/* ---------- Traitement d'image ---------- */
async function decode(file){
  if (window.createImageBitmap) {
    try { return await createImageBitmap(file, {imageOrientation: "from-image"}); } catch(e) {}
  }
  return await new Promise((res, rej) => {
    const url = URL.createObjectURL(file); const img = new Image();
    img.onload = () => { res(img); setTimeout(() => URL.revokeObjectURL(url), 1000); };
    img.onerror = () => { URL.revokeObjectURL(url); rej(new Error("format d'image non pris en charge par ce navigateur (essayez JPEG)")); };
    img.src = url;
  });
}
function toCanvas(img, maxDim){
  const w0 = img.width || img.naturalWidth, h0 = img.height || img.naturalHeight;
  const s = Math.min(1, maxDim / Math.max(w0, h0));
  const c = document.createElement("canvas"); c.width = Math.round(w0 * s); c.height = Math.round(h0 * s);
  c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
  return c;
}
async function loadSource(it){
  const img = await decode(it.file);
  const c = toCanvas(img, MAX_SRC);
  if (img.close) img.close();
  it.w = c.width; it.h = c.height;
  return c;
}

async function prepare(it){
  it.msg = ""; it.tooBig = false;
  if (it.kind === "pdf") {
    it.out = it.file; it.outType = "application/pdf";
    if (it.file.size > MAX_UPLOAD) { it.tooBig = true; it.msg = "PDF trop lourd (" + fmtSize(it.file.size) + ")."; }
    return;
  }
  const src = await loadSource(it);
  if (!it.corners) { it.auto = detectQuad(src); it.corners = it.auto ? it.auto.map(p => p.slice()) : fullQuad(it.w, it.h); }
  await renderOutput(it, src);
}
function fullQuad(w, h){ return [[0,0],[w,0],[w,h],[0,h]]; }

async function renderOutput(it, src){
  let doc = warp(src, it.corners);
  if (it.rot) doc = rotate(doc, it.rot);
  if (it.bw) toBw(doc);
  const target = PHOTO_TARGET;
  const jpg = await encodeJpeg(doc, target);
  if (opt.pdf) {
    const bytes = new Uint8Array(await jpg.arrayBuffer());
    it.out = new Blob([jpegToPdf(bytes, doc.width, doc.height)], {type: "application/pdf"}); it.outType = "application/pdf";
  } else { it.out = jpg; it.outType = "image/jpeg"; }
  it.pdfFlag = opt.pdf;
  const t = toCanvas(doc, 240);
  if (it.thumb) URL.revokeObjectURL(it.thumb);
  it.thumb = URL.createObjectURL(await new Promise(r => t.toBlob(r, "image/jpeg", .8)));
  if (it.out.size > MAX_UPLOAD) { it.tooBig = true; it.msg = "Document trop lourd."; }
}
async function encodeJpeg(canvas, maxBytes){
  let c = canvas, q = .85, blob;
  for (let i = 0; i < 10; i++) {
    blob = await new Promise(r => c.toBlob(r, "image/jpeg", q));
    if (blob.size <= maxBytes) return blob;
    if (q > .62) q -= .08; else { c = toCanvas(c, Math.round(Math.max(c.width, c.height) * .82)); }
  }
  return blob;
}

/* Détection du document : contours (Sobel) puis repli sur la luminosité */
function detectQuad(src){
  const S = 420, sc = Math.min(1, S / Math.max(src.width, src.height));
  const w = Math.max(8, Math.round(src.width * sc)), h = Math.max(8, Math.round(src.height * sc));
  const c = document.createElement("canvas"); c.width = w; c.height = h;
  const ctx = c.getContext("2d", {willReadFrequently: true}); ctx.drawImage(src, 0, 0, w, h);
  const d = ctx.getImageData(0, 0, w, h).data, N = w * h;
  let g = new Float32Array(N);
  for (let i = 0; i < N; i++) g[i] = .299 * d[i*4] + .587 * d[i*4+1] + .114 * d[i*4+2];
  g = boxBlur(boxBlur(g, w, h, 2), w, h, 2);

  const cands = [];
  // A. contours
  const mag = new Float32Array(N);
  for (let y = 1; y < h - 1; y++) for (let x = 1; x < w - 1; x++) {
    const i = y * w + x;
    const gx = g[i-w+1] + 2*g[i+1] + g[i+w+1] - g[i-w-1] - 2*g[i-1] - g[i+w-1];
    const gy = g[i+w-1] + 2*g[i+w] + g[i+w+1] - g[i-w-1] - 2*g[i-w] - g[i-w+1];
    mag[i] = Math.hypot(gx, gy);
  }
  for (const pct of [.88, .8, .93]) {
    const thr = Math.max(28, percentile(mag, pct));
    let edge = new Uint8Array(N); for (let i = 0; i < N; i++) edge[i] = mag[i] > thr ? 1 : 0;
    edge = dilate(edge, w, h, 2);
    const bg = floodBorder(edge, w, h);
    const region = new Uint8Array(N); for (let i = 0; i < N; i++) region[i] = bg[i] ? 0 : 1;
    const q = quadFromMask(region, w, h); if (q) { q.inset = 3.2; cands.push(q); }
  }
  // B. luminosité (Otsu)
  const t = otsu(g);
  for (const inv of [false, true]) {
    let m = new Uint8Array(N); for (let i = 0; i < N; i++) m[i] = (g[i] > t) !== inv ? 1 : 0;
    m = erode(dilate(m, w, h, 3), w, h, 3);
    m = dilate(erode(m, w, h, 2), w, h, 2);
    const q = quadFromMask(m, w, h); if (q) { q.score -= .05; cands.push(q); }
  }
  if (!cands.length) return null;
  cands.sort((a, b) => b.score - a.score);
  const best = cands[0];
  if (best.score < .55) return null;
  if (best.inset) { const cx = best.pts.reduce((a, p) => a + p[0], 0) / 4, cy = best.pts.reduce((a, p) => a + p[1], 0) / 4;
    best.pts = best.pts.map(([x, y]) => { const L = Math.hypot(cx - x, cy - y) || 1; return [x + (cx - x) / L * best.inset, y + (cy - y) / L * best.inset]; }); }
  return best.pts.map(([x, y]) => [Math.min(src.width, Math.max(0, x / sc)), Math.min(src.height, Math.max(0, y / sc))]);
}
function boxBlur(a, w, h, r){
  const t = new Float32Array(a.length), o = new Float32Array(a.length);
  for (let y = 0; y < h; y++) { let s = 0, n = 0; for (let x = -r; x < w + r; x++) {
      if (x + r < w && x + r >= 0) { s += a[y*w + x + r]; n++; }
      if (x - r - 1 >= 0) { s -= a[y*w + x - r - 1]; n--; }
      if (x >= 0 && x < w) t[y*w + x] = s / n; } }
  for (let x = 0; x < w; x++) { let s = 0, n = 0; for (let y = -r; y < h + r; y++) {
      if (y + r < h && y + r >= 0) { s += t[(y + r)*w + x]; n++; }
      if (y - r - 1 >= 0) { s -= t[(y - r - 1)*w + x]; n--; }
      if (y >= 0 && y < h) o[y*w + x] = s / n; } }
  return o;
}
function percentile(a, p){ const s = Float32Array.from(a).sort(); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; }
function otsu(g){
  const hist = new Float64Array(256); for (const v of g) hist[Math.min(255, Math.max(0, v | 0))]++;
  const total = g.length; let sum = 0; for (let i = 0; i < 256; i++) sum += i * hist[i];
  let sB = 0, wB = 0, best = 0, thr = 127;
  for (let i = 0; i < 256; i++) { wB += hist[i]; if (!wB) continue; const wF = total - wB; if (!wF) break;
    sB += i * hist[i]; const mB = sB / wB, mF = (sum - sB) / wF, v = wB * wF * (mB - mF) ** 2; if (v > best) { best = v; thr = i; } }
  return thr;
}
function dilate(m, w, h, r){ return morph(m, w, h, r, 1); }
function erode(m, w, h, r){ return morph(m, w, h, r, 0); }
function morph(m, w, h, r, val){
  const t = new Uint8Array(m.length), o = new Uint8Array(m.length);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { let hit = val ? 0 : 1;
    for (let k = -r; k <= r; k++) { const xx = x + k; if (xx < 0 || xx >= w) { if (!val) { hit = 0; break; } continue; } if (m[y*w + xx] === val) { hit = val; break; } }
    t[y*w + x] = hit; }
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { let hit = val ? 0 : 1;
    for (let k = -r; k <= r; k++) { const yy = y + k; if (yy < 0 || yy >= h) { if (!val) { hit = 0; break; } continue; } if (t[yy*w + x] === val) { hit = val; break; } }
    o[y*w + x] = hit; }
  return o;
}
function floodBorder(edge, w, h){
  const bg = new Uint8Array(w * h), st = [];
  const push = i => { if (!edge[i] && !bg[i]) { bg[i] = 1; st.push(i); } };
  for (let x = 0; x < w; x++) { push(x); push((h - 1) * w + x); }
  for (let y = 0; y < h; y++) { push(y * w); push(y * w + w - 1); }
  while (st.length) { const i = st.pop(), x = i % w, y = (i / w) | 0;
    if (x > 0) push(i - 1); if (x < w - 1) push(i + 1); if (y > 0) push(i - w); if (y < h - 1) push(i + w); }
  return bg;
}
function quadFromMask(m, w, h){
  // plus grande composante connexe
  const lab = new Int32Array(w * h); let best = 0, bestLab = 0, cur = 0; const st = [];
  for (let s = 0; s < w * h; s++) { if (!m[s] || lab[s]) continue; cur++; let n = 0; lab[s] = cur; st.push(s);
    while (st.length) { const i = st.pop(); n++; const x = i % w, y = (i / w) | 0;
      if (x > 0 && m[i-1] && !lab[i-1]) { lab[i-1] = cur; st.push(i-1); }
      if (x < w-1 && m[i+1] && !lab[i+1]) { lab[i+1] = cur; st.push(i+1); }
      if (y > 0 && m[i-w] && !lab[i-w]) { lab[i-w] = cur; st.push(i-w); }
      if (y < h-1 && m[i+w] && !lab[i+w]) { lab[i+w] = cur; st.push(i+w); } }
    if (n > best) { best = n; bestLab = cur; } }
  const frac = best / (w * h);
  if (frac < .2 || frac > .985) return null;
  const pts = [];
  for (let y = 0; y < h; y++) { let a = -1, b = -1; for (let x = 0; x < w; x++) if (lab[y*w + x] === bestLab) { if (a < 0) a = x; b = x; }
    if (a >= 0) { pts.push([a, y], [b + 1, y], [a, y + 1], [b + 1, y + 1]); } }
  let hull = convexHull(pts); if (hull.length < 4) return null;
  hull = simplify(hull, 1.2);
  if (hull.length > 40) { const st2 = hull.length / 40; hull = Array.from({length: 40}, (_, i) => hull[Math.floor(i * st2)]); }
  const q = maxQuad(hull); if (!q) return null;
  const qa = polyArea(q), ha = polyArea(convexHull(pts));
  const fill = best / qa, cover = qa / ha;
  // pénalise un quadrilatère qui touche tout le bord de l'image (fond détecté)
  const touch = q.filter(([x, y]) => x < 2 || y < 2 || x > w - 2 || y > h - 2).length;
  const oq = orderQuad(q);
  // un document photographié de face a des angles proches de 90° : on écarte les formes trop biaisées
  let worst = 0;
  for (let i = 0; i < 4; i++) { const a = oq[(i + 3) % 4], b = oq[i], c = oq[(i + 1) % 4];
    const v1 = [a[0]-b[0], a[1]-b[1]], v2 = [c[0]-b[0], c[1]-b[1]];
    const ang = Math.acos(Math.max(-1, Math.min(1, (v1[0]*v2[0] + v1[1]*v2[1]) / ((Math.hypot(...v1) * Math.hypot(...v2)) || 1)))) * 180 / Math.PI;
    worst = Math.max(worst, Math.abs(ang - 90)); }
  const score = Math.min(1, fill) * .6 + Math.min(1, cover) * .4 - touch * .08 - (frac > .93 ? .1 : 0) - (worst > 25 ? .6 : worst > 15 ? .35 : 0);
  return {pts: oq, score, frac};
}
function convexHull(p){
  const pts = p.slice().sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const cr = (o, a, b) => (a[0]-o[0])*(b[1]-o[1]) - (a[1]-o[1])*(b[0]-o[0]);
  const lo = [], up = [];
  for (const q of pts) { while (lo.length >= 2 && cr(lo[lo.length-2], lo[lo.length-1], q) <= 0) lo.pop(); lo.push(q); }
  for (let i = pts.length - 1; i >= 0; i--) { const q = pts[i]; while (up.length >= 2 && cr(up[up.length-2], up[up.length-1], q) <= 0) up.pop(); up.push(q); }
  return lo.slice(0, -1).concat(up.slice(0, -1));
}
function simplify(poly, eps){
  // supprime les sommets quasi alignés
  let p = poly.slice(), changed = true;
  while (changed && p.length > 4) { changed = false;
    for (let i = 0; i < p.length && p.length > 4; i++) { const a = p[(i - 1 + p.length) % p.length], b = p[i], c = p[(i + 1) % p.length];
      const L = Math.hypot(c[0]-a[0], c[1]-a[1]) || 1; const dist = Math.abs((c[0]-a[0])*(a[1]-b[1]) - (a[0]-b[0])*(c[1]-a[1])) / L;
      if (dist < eps) { p.splice(i, 1); changed = true; i--; } } }
  return p;
}
function polyArea(p){ let s = 0; for (let i = 0; i < p.length; i++) { const a = p[i], b = p[(i + 1) % p.length]; s += a[0]*b[1] - b[0]*a[1]; } return Math.abs(s) / 2; }
function maxQuad(h){
  const n = h.length; if (n === 4) return h.slice(); let best = 0, bq = null;
  const tri = (a, b, c) => Math.abs((b[0]-a[0])*(c[1]-a[1]) - (c[0]-a[0])*(b[1]-a[1])) / 2;
  for (let i = 0; i < n; i++) for (let k = i + 2; k < n; k++) {
    let m1 = 0, j1 = -1; for (let j = i + 1; j < k; j++) { const t = tri(h[i], h[j], h[k]); if (t > m1) { m1 = t; j1 = j; } }
    let m2 = 0, l1 = -1; for (let l = k + 1; l < n + i; l++) { const t = tri(h[i], h[k], h[l % n]); if (t > m2) { m2 = t; l1 = l % n; } }
    if (j1 >= 0 && l1 >= 0 && m1 + m2 > best) { best = m1 + m2; bq = [h[i], h[j1], h[k], h[l1]]; } }
  return bq;
}
function orderQuad(q){
  const cx = q.reduce((s, p) => s + p[0], 0) / 4, cy = q.reduce((s, p) => s + p[1], 0) / 4;
  const s = q.slice().sort((a, b) => Math.atan2(a[1]-cy, a[0]-cx) - Math.atan2(b[1]-cy, b[0]-cx)); // horaire (y vers le bas)
  let k = 0, m = Infinity; s.forEach((p, i) => { if (p[0] + p[1] < m) { m = p[0] + p[1]; k = i; } });
  return [0, 1, 2, 3].map(i => s[(k + i) % 4]); // HG, HD, BD, BG
}
function homography(src, dst){
  // trouve H tel que dst ≈ H·src
  const A = [], b = [];
  for (let i = 0; i < 4; i++) { const [x, y] = src[i], [u, v] = dst[i];
    A.push([x, y, 1, 0, 0, 0, -u*x, -u*y]); b.push(u);
    A.push([0, 0, 0, x, y, 1, -v*x, -v*y]); b.push(v); }
  for (let c = 0; c < 8; c++) { let p = c; for (let r = c + 1; r < 8; r++) if (Math.abs(A[r][c]) > Math.abs(A[p][c])) p = r;
    [A[c], A[p]] = [A[p], A[c]]; [b[c], b[p]] = [b[p], b[c]];
    for (let r = 0; r < 8; r++) if (r !== c) { const f = A[r][c] / A[c][c]; for (let k = c; k < 8; k++) A[r][k] -= f * A[c][k]; b[r] -= f * b[c]; } }
  return b.map((v, i) => v / A[i][i]).concat([1]);
}
function warp(src, corners){
  const [tl, tr, br, bl] = corners, dist = (a, b) => Math.hypot(a[0]-b[0], a[1]-b[1]);
  let W = Math.max(dist(tl, tr), dist(bl, br)), H = Math.max(dist(tl, bl), dist(tr, br));
  const s = Math.min(1, MAX_OUT / Math.max(W, H)); W = Math.max(1, Math.round(W * s)); H = Math.max(1, Math.round(H * s));
  const isFull = corners.every((p, i) => { const f = fullQuad(src.width, src.height)[i]; return Math.abs(p[0]-f[0]) < 1 && Math.abs(p[1]-f[1]) < 1; });
  const out = document.createElement("canvas"); out.width = W; out.height = H;
  const octx = out.getContext("2d");
  if (isFull) { octx.drawImage(src, 0, 0, W, H); return out; }
  const sw = src.width, sh = src.height;
  const sd = src.getContext("2d", {willReadFrequently: true}).getImageData(0, 0, sw, sh).data;
  const od = octx.createImageData(W, H), o = od.data;
  const M = homography([[0,0],[W,0],[W,H],[0,H]], corners);
  for (let y = 0; y < H; y++) { for (let x = 0; x < W; x++) {
      const X = x + .5, Y = y + .5, den = M[6]*X + M[7]*Y + 1;
      let u = (M[0]*X + M[1]*Y + M[2]) / den - .5, v = (M[3]*X + M[4]*Y + M[5]) / den - .5;
      if (u < 0) u = 0; if (v < 0) v = 0; if (u > sw - 1.001) u = sw - 1.001; if (v > sh - 1.001) v = sh - 1.001;
      const x0 = u | 0, y0 = v | 0, fx = u - x0, fy = v - y0, i0 = (y0*sw + x0) * 4, i1 = i0 + sw * 4, oi = (y*W + x) * 4;
      for (let c = 0; c < 3; c++) { const a = sd[i0+c] + (sd[i0+4+c] - sd[i0+c]) * fx, b2 = sd[i1+c] + (sd[i1+4+c] - sd[i1+c]) * fx; o[oi+c] = a + (b2 - a) * fy; }
      o[oi+3] = 255; } }
  octx.putImageData(od, 0, 0);
  return out;
}
function rotate(c, deg){
  const r = ((deg % 360) + 360) % 360; if (!r) return c;
  const o = document.createElement("canvas"); const swap = r === 90 || r === 270;
  o.width = swap ? c.height : c.width; o.height = swap ? c.width : c.height;
  const x = o.getContext("2d"); x.translate(o.width / 2, o.height / 2); x.rotate(r * Math.PI / 180); x.drawImage(c, -c.width / 2, -c.height / 2);
  return o;
}
function toBw(c){
  const x = c.getContext("2d"), id = x.getImageData(0, 0, c.width, c.height), d = id.data, n = d.length / 4;
  const hist = new Uint32Array(256), g = new Uint8ClampedArray(n);
  for (let i = 0; i < n; i++) { const v = .299*d[i*4] + .587*d[i*4+1] + .114*d[i*4+2]; g[i] = v; hist[g[i]]++; }
  let lo = 0, hi = 255, acc = 0; for (let i = 0; i < 256; i++) { acc += hist[i]; if (acc > n * .02) { lo = i; break; } }
  acc = 0; for (let i = 255; i >= 0; i--) { acc += hist[i]; if (acc > n * .1) { hi = i; break; } }
  const k = 255 / Math.max(1, hi - lo);
  for (let i = 0; i < n; i++) { const v = (g[i] - lo) * k; d[i*4] = d[i*4+1] = d[i*4+2] = v; }
  x.putImageData(id, 0, 0);
}
/* PDF minimal : une page, une image JPEG */
function jpegToPdf(jpg, w, h){
  const long = 842, s = long / Math.max(w, h), pw = +(w * s).toFixed(2), ph = +(h * s).toFixed(2);
  const enc = new TextEncoder(), parts = [], offs = []; let len = 0;
  const add = x => { const b = typeof x === "string" ? enc.encode(x) : x; parts.push(b); len += b.length; };
  const obj = (n, body) => { offs[n] = len; add(n + " 0 obj\n"); body(); add("\nendobj\n"); };
  add("%PDF-1.4\n"); add(new Uint8Array([37, 226, 227, 207, 211, 10]));
  const content = "q " + pw + " 0 0 " + ph + " 0 0 cm /Im0 Do Q";
  obj(1, () => add("<< /Type /Catalog /Pages 2 0 R >>"));
  obj(2, () => add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"));
  obj(3, () => add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + pw + " " + ph + "] /Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>"));
  obj(4, () => add("<< /Length " + content.length + " >>\nstream\n" + content + "\nendstream"));
  obj(5, () => { add("<< /Type /XObject /Subtype /Image /Width " + w + " /Height " + h + " /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length " + jpg.length + " >>\nstream\n"); add(jpg); add("\nendstream"); });
  const xref = len;
  let x = "xref\n0 6\n0000000000 65535 f \n"; for (let i = 1; i <= 5; i++) x += String(offs[i]).padStart(10, "0") + " 00000 n \n";
  add(x + "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + xref + "\n%%EOF\n");
  const out = new Uint8Array(len); let p = 0; for (const b of parts) { out.set(b, p); p += b.length; } return out;
}

/* ---------- Éditeur de cadrage ---------- */
let ed = null;
async function openEditor(it){
  if (it.kind !== "image") return;
  const src = await loadSource(it);
  ed = { it, src, corners: it.corners.map(p => p.slice()), rot: it.rot, bw: it.bw, drag: -1 };
  $("editor").hidden = false;
  const cv = $("edCanvas"); const stage = $("stage");
  const sc = Math.min(1, (stage.clientWidth - 24) / src.width, (stage.clientHeight - 24) / src.height);
  cv.width = Math.round(src.width * Math.min(1, 1600 / Math.max(src.width, src.height)));
  cv.height = Math.round(src.height * cv.width / src.width);
  cv.getContext("2d").drawImage(src, 0, 0, cv.width, cv.height);
  cv.style.width = Math.round(src.width * sc) + "px"; cv.style.height = Math.round(src.height * sc) + "px";
  edRender();
}
function edGeom(){
  const cv = $("edCanvas"), r = cv.getBoundingClientRect(), sr = $("stage").getBoundingClientRect();
  return { ox: r.left - sr.left, oy: r.top - sr.top, k: r.width / ed.src.width, r };
}
function edRender(){
  if (!ed) return;
  const g = edGeom(), svg = $("edSvg");
  const P = ed.corners.map(([x, y]) => [g.ox + x * g.k, g.oy + y * g.k]);
  const ns = "http://www.w3.org/2000/svg";
  svg.textContent = "";
  const r = g.r, sr = $("stage").getBoundingClientRect();
  const x0 = r.left - sr.left, y0 = r.top - sr.top, x1 = x0 + r.width, y1 = y0 + r.height;
  const scrim = document.createElementNS(ns, "path");
  scrim.setAttribute("d", "M" + x0 + "," + y0 + "H" + x1 + "V" + y1 + "H" + x0 + "Z M" + P.map(p => p.join(",")).join(" L") + "Z");
  scrim.setAttribute("fill", "rgba(0,0,0,.45)"); scrim.setAttribute("fill-rule", "evenodd"); svg.append(scrim);
  const poly = document.createElementNS(ns, "polygon");
  poly.setAttribute("points", P.map(p => p.join(",")).join(" "));
  poly.setAttribute("fill", "none"); poly.setAttribute("stroke", "var(--accent)"); poly.setAttribute("stroke-width", "2.5");
  svg.append(poly);
  P.forEach(([x, y]) => { const c = document.createElementNS(ns, "circle"); c.setAttribute("cx", x); c.setAttribute("cy", y); c.setAttribute("r", 13);
    c.setAttribute("fill", "var(--surface)"); c.setAttribute("stroke", "var(--accent)"); c.setAttribute("stroke-width", "3"); svg.append(c); });
  edgeMids(P).forEach(([x, y], i) => { const c = document.createElementNS(ns, "rect"); const hz = i % 2 === 0;
    c.setAttribute("x", x - (hz ? 16 : 6)); c.setAttribute("y", y - (hz ? 6 : 16)); c.setAttribute("width", hz ? 32 : 12); c.setAttribute("height", hz ? 12 : 32); c.setAttribute("rx", 6);
    c.setAttribute("fill", "var(--surface)"); c.setAttribute("stroke", "var(--accent)"); c.setAttribute("stroke-width", "2.5"); svg.append(c); });
  $("edRotInfo").textContent = "Rotation " + ed.rot + "°";
  $("edColor").setAttribute("aria-pressed", String(!ed.bw)); $("edBw").setAttribute("aria-pressed", String(ed.bw));
}
function edgeMids(P){ return [0, 1, 2, 3].map(i => { const a = P[i], b = P[(i + 1) % 4]; return [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2]; }); }
const stageEl = $("stage");
stageEl.addEventListener("pointerdown", e => {
  if (!ed) return; const g = edGeom(), sr = stageEl.getBoundingClientRect();
  const px = e.clientX - sr.left, py = e.clientY - sr.top; let best = -1, bd = 44;
  const P = ed.corners.map(([x, y]) => [g.ox + x * g.k, g.oy + y * g.k]);
  P.forEach(([x, y], i) => { const d = Math.hypot(x - px, y - py); if (d < bd) { bd = d; best = i; } });
  edgeMids(P).forEach(([x, y], i) => { const d = Math.hypot(x - px, y - py) + 6; if (d < bd) { bd = d; best = 4 + i; } });
  if (best >= 0) { ed.drag = best; ed.last = [(px - g.ox) / g.k, (py - g.oy) / g.k]; stageEl.setPointerCapture(e.pointerId); e.preventDefault(); }
});
stageEl.addEventListener("pointermove", e => {
  if (!ed || ed.drag < 0) return; const g = edGeom(), sr = stageEl.getBoundingClientRect();
  const x = (e.clientX - sr.left - g.ox) / g.k, y = (e.clientY - sr.top - g.oy) / g.k;
  const clamp = ([u, v]) => [Math.max(0, Math.min(ed.src.width, u)), Math.max(0, Math.min(ed.src.height, v))];
  if (ed.drag < 4) ed.corners[ed.drag] = clamp([x, y]);
  else { const i = ed.drag - 4, j = (i + 1) % 4, dx = x - ed.last[0], dy = y - ed.last[1];
    ed.corners[i] = clamp([ed.corners[i][0] + dx, ed.corners[i][1] + dy]); ed.corners[j] = clamp([ed.corners[j][0] + dx, ed.corners[j][1] + dy]); }
  ed.last = [x, y]; edRender();
});
const endDrag = () => { if (ed) ed.drag = -1; };
stageEl.addEventListener("pointerup", endDrag); stageEl.addEventListener("pointercancel", endDrag);
window.addEventListener("resize", () => { if (ed) { const src = ed.src, stage = $("stage"), cv = $("edCanvas");
  const sc = Math.min(1, (stage.clientWidth - 24) / src.width, (stage.clientHeight - 24) / src.height);
  cv.style.width = Math.round(src.width * sc) + "px"; cv.style.height = Math.round(src.height * sc) + "px"; edRender(); } });
$("edAuto").onclick = () => { const q = detectQuad(ed.src); if (q) ed.corners = q; else { ed.corners = fullQuad(ed.src.width, ed.src.height); } edRender(); };
$("edFull").onclick = () => { ed.corners = fullQuad(ed.src.width, ed.src.height); edRender(); };
$("edRotL").onclick = () => { ed.rot = (ed.rot + 270) % 360; edRender(); };
$("edRotR").onclick = () => { ed.rot = (ed.rot + 90) % 360; edRender(); };
$("edColor").onclick = () => { ed.bw = false; edRender(); };
$("edBw").onclick = () => { ed.bw = true; edRender(); };
$("edCancel").onclick = () => { ed = null; $("editor").hidden = true; };
$("edOk").onclick = async () => {
  const { it, src } = ed; it.corners = orderQuad(ed.corners); it.rot = ed.rot; it.bw = ed.bw;
  ed = null; $("editor").hidden = true;
  it.status = "processing"; render();
  try { it.msg = ""; it.tooBig = false; await renderOutput(it, src); it.status = it.tooBig ? "error" : "ready"; }
  catch(e) { it.status = "error"; it.msg = "Traitement impossible : " + (e.message || e); }
  render();
};
async function quickRotate(it, delta){
  it.rot = (it.rot + delta + 360) % 360; it.status = "processing"; render();
  try { const src = await loadSource(it); it.msg = ""; it.tooBig = false; await renderOutput(it, src); it.status = it.tooBig ? "error" : "ready"; }
  catch(e) { it.status = "error"; it.msg = String(e.message || e); }
  render();
}

/* ---------- Envoi ---------- */
function extOf(it){ return it.kind === "pdf" ? ".pdf" : (it.outType === "application/pdf" ? ".pdf" : ".jpg"); }
function refreshNames(){
  for (const it of items) if (it.kind === "image" && (it.status === "ready" || it.status === "error") && it.pdfFlag !== opt.pdf) it.status = "queued";
  pump(); render();
}
async function uploadBlob(parentId, filename, blob){
  const name = encodeURIComponent(filename);
  if (blob.size <= 4 * 1024 * 1024) {
    return graph("/me/drive/items/" + parentId + ":/" + name + ":/content?@microsoft.graph.conflictBehavior=rename",
      { method: "PUT", body: blob, headers: {"Content-Type": blob.type || "application/octet-stream"} });
  }
  const s = await graph("/me/drive/items/" + parentId + ":/" + name + ":/createUploadSession",
    { method: "POST", json: {item: {"@microsoft.graph.conflictBehavior": "rename"}} });
  const CH = 320 * 1024 * 10;
  for (let start = 0; start < blob.size; start += CH) {
    const end = Math.min(blob.size, start + CH);
    const r = await fetch(s.uploadUrl, { method: "PUT", body: blob.slice(start, end),
      headers: {"Content-Range": "bytes " + start + "-" + (end - 1) + "/" + blob.size} });
    if (!r.ok && r.status !== 202) { const e = new Error("HTTP " + r.status); e.status = r.status; throw e; }
    if (end === blob.size) return r.json();
  }
}
async function sendAll(){
  if (sending || !auth.signedIn || !dest) return;
  const todo = items.filter(x => x.status === "ready" || (x.status === "error" && x.sendFailed));
  if (!todo.length) return;
  sending = true; render();
  const target = dest[dest.length - 1], where = dest.map(d => d.name).join(" / ");
  for (const it of todo) {
    it.status = "sending"; it.msg = ""; it.sendFailed = false; render();
    const filename = (it.base || "document").slice(0, 180) + extOf(it);
    try {
      const res = await uploadBlob(target.id, filename, it.out);
      it.webUrl = res && res.webUrl || ""; it.sentName = res && res.name || filename; it.sentTo = where;
      it.status = "sent";
      if (res && res.id) addHist({ id: res.id, name: it.sentName, webUrl: it.webUrl, at: Date.now() });
    } catch(e) { it.status = "error"; it.sendFailed = true; it.msg = errText(e); }
    render();
  }
  sending = false; render(); renderTracking();
  setTimeout(refreshTracking, 1500);
}
$("sendBtn").onclick = sendAll;
$("clearDone").onclick = () => { items = items.filter(x => { if (x.status === "sent") { if (x.thumb) URL.revokeObjectURL(x.thumb); return false; } return true; }); render(); };


/* ---------- Suivi : renommage, classement, rapprochement ---------- */
const API_URL = (CFG.apiUrl || "").replace(/\/$/, "");
const EXPENSES_PATH = CFG.expensesPath || "";
function histKey(){ return "scanner.hist." + (auth.user ? auth.user.id : ""); }
function loadHist(){ return store.get(histKey(), []); }
function addHist(e){ const h = loadHist().filter(x => x.id !== e.id); h.unshift(e); store.set(histKey(), h.slice(0, 40)); }
let trackState = { rows: [], loading: false, at: 0, err: "" };
let qontoRows = null; // lignes « Qonto e-facture » du tableau, null tant que non lues
function xlDate(v){ if (typeof v === "number") { const d = new Date(Math.round((v - 25569) * 86400000)); return d.toLocaleDateString("fr-FR", {timeZone: "UTC"}); } return String(v || ""); }
function eur(v){ const n = +v; return isFinite(n) && v !== "" ? n.toLocaleString("fr-FR", {minimumFractionDigits: 2, maximumFractionDigits: 2}) + " €" : String(v || ""); }

async function refreshTracking(){
  if (!auth.signedIn || trackState.loading) return;
  const hist = loadHist();
  trackState.loading = true; trackState.err = ""; renderTracking();
  try {
    const info = {};
    for (let i = 0; i < hist.length; i += 20) {
      const chunk = hist.slice(i, i + 20);
      const r = await graph("/$batch", { method: "POST", json: { requests: chunk.map((h, k) => ({ id: String(k), method: "GET",
        url: "/me/drive/items/" + h.id + "?$select=id,name,webUrl,parentReference" })) } });
      for (const resp of r.responses) { const h = chunk[+resp.id]; info[h.id] = resp.status === 200 ? resp.body : { missing: true }; }
    }
    let qonto = {};
    if (EXPENSES_PATH) {
      try {
        const p = EXPENSES_PATH.split("/").map(encodeURIComponent).join("/");
        const u = await graph("/me/drive/root:/" + p + ":/workbook/worksheets('D%C3%A9penses')/usedRange(valuesOnly=true)?$select=values");
        const vals = u.values || [], head = vals[0] || [];
        const iName = head.findIndex(x => /justificatif/i.test(x)), iQ = head.findIndex(x => /qonto/i.test(x));
        for (const row of vals.slice(1)) if (row[iName]) qonto[String(row[iName]).trim()] = String(row[iQ] || "").trim();
        const col = re => head.findIndex(x => re.test(String(x)));
        const iSrc = col(/^source/i), iD = col(/^date$/i), iF = col(/fournisseur/i), iN = col(/n° ?facture|numéro/i), iT = col(/TTC/i);
        if (iSrc >= 0) qontoRows = vals.slice(1).filter(r => /qonto e-facture/i.test(String(r[iSrc]))).map(r => ({
          date: r[iD], dateTxt: xlDate(r[iD]), fournisseur: r[iF], numero: r[iN], ttc: r[iT], q: String(r[iQ] || "").trim() }))
          .sort((a, b) => (+b.date || 0) - (+a.date || 0));
      } catch(e) { /* tableau absent ou illisible : le rapprochement s'affiche « inconnu » */ }
    }
    trackState.rows = hist.map(h => {
      const it = info[h.id] || {};
      const path = it.parentReference && it.parentReference.path ? decodeURIComponent(it.parentReference.path.replace(/^.*root:/, "")) : "";
      const name = it.name || h.name;
      const renamed = /^\d{8}_.+€TTC\.\w+$/.test(name);
      const where = /\/Fournisseurs\//.test(path) ? "classe" : /À vérifier/.test(path) ? "verifier" : it.missing ? "absent" : "attente";
      const q = qonto[name] || "";
      const matched = /joint|déjà justifi/i.test(q) ? "ok" : /valider/i.test(q) ? "valider" : q ? "autre" : "";
      return { ...h, name, webUrl: it.webUrl || h.webUrl, path, renamed, where, q, matched };
    });
    trackState.at = Date.now();
  } catch(e) { trackState.err = errText(e); }
  trackState.loading = false; renderTracking(); renderQonto();
}

function renderQonto(){
  const box = $("qontoBox"); if (!box) return;
  box.hidden = !auth.signedIn;
  const list = $("qontoList"); list.textContent = "";
  if (qontoRows === null) { $("qontoInfo").textContent = trackState.loading ? "Mise à jour…" : ""; return; }
  const total = qontoRows.reduce((s, r) => s + (+r.ttc || 0), 0);
  const aValider = qontoRows.filter(r => /valider/i.test(r.q)).length;
  $("qontoInfo").textContent = qontoRows.length
    ? qontoRows.length + " facture" + (qontoRows.length > 1 ? "s" : "") + " importée" + (qontoRows.length > 1 ? "s" : "") + " · " + eur(total) + " TTC" + (aValider ? " · " + aValider + " à valider dans Qonto" : "")
    : "Aucune facture électronique importée pour l'instant.";
  for (const r of qontoRows.slice(0, 15)) {
    const el = document.createElement("div"); el.className = "trow";
    const nm = document.createElement("div"); nm.className = "tname"; nm.textContent = (r.fournisseur || "?") + " · " + eur(r.ttc);
    const chips = document.createElement("div"); chips.className = "row";
    chips.append(/joint|déjà justifi/i.test(r.q) ? chip("✓ Payée", "ok", r.q) : /valider/i.test(r.q) ? chip("… À valider", "warn", "À payer ou valider dans Qonto") : chip(r.q || "?", ""));
    const when = document.createElement("div"); when.className = "hint"; when.textContent = r.dateTxt + (r.numero ? " · n° " + r.numero : "");
    el.append(nm, chips, when); list.append(el);
  }
  if (qontoRows.length > 15) { const more = document.createElement("div"); more.className = "hint"; more.textContent = "… et " + (qontoRows.length - 15) + " autres dans le tableau des dépenses."; list.append(more); }
}

function chip(text, cls, title){ const s = document.createElement("span"); s.className = "pill " + (cls || ""); s.textContent = text; if (title) s.title = title; return s; }
function renderTracking(){
  const box = $("track"); if (!box) return;
  box.hidden = !auth.signedIn;
  const list = $("trackList"); list.textContent = "";
  $("trackRefresh").disabled = trackState.loading;
  $("trackInfo").textContent = trackState.loading ? "Mise à jour…" : trackState.err ? trackState.err
    : trackState.at ? "Mis à jour à " + new Date(trackState.at).toLocaleTimeString("fr-FR", {hour: "2-digit", minute: "2-digit"}) : "";
  const rows = trackState.rows.length ? trackState.rows : loadHist().map(h => ({...h, pending: true}));
  if (!rows.length) { list.innerHTML = '<div class="fstate">Les documents envoyés apparaîtront ici avec leur état de traitement.</div>'; return; }
  for (const r of rows) {
    const el = document.createElement("div"); el.className = "trow";
    const nm = document.createElement(r.webUrl ? "a" : "div"); nm.className = "tname"; nm.textContent = r.name;
    if (r.webUrl) { nm.href = r.webUrl; nm.target = "_blank"; nm.rel = "noopener"; }
    const chips = document.createElement("div"); chips.className = "row";
    if (r.pending) chips.append(chip("Envoyé", "ok"));
    else if (r.where === "absent") chips.append(chip("Introuvable", "warn", "Déplacé hors de portée ou supprimé"));
    else {
      chips.append(r.renamed ? chip("✓ Renommé", "ok") : chip("○ À renommer", ""));
      chips.append(r.where === "classe" ? chip("✓ Classé", "ok", r.path) : r.where === "verifier" ? chip("! À vérifier", "warn", r.path) : chip("○ À classer", ""));
      chips.append(r.matched === "ok" ? chip("✓ Rapproché", "ok", r.q) : r.matched === "valider" ? chip("… Qonto à valider", "warn", "Validez le rattachement dans le fil Claude") : r.q ? chip(r.q, "") : chip("○ Rapprochement", ""));
    }
    const when = document.createElement("div"); when.className = "hint"; when.textContent = "Envoyé le " + new Date(r.at).toLocaleString("fr-FR", {day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"});
    el.append(nm, chips, when); list.append(el);
  }
}
$("trackRefresh").onclick = refreshTracking;

async function runNow(mode){
  mode = mode === "qonto" ? "qonto" : "";
  const btn = $(mode ? "qontoImport" : "runNow"), msg = $(mode ? "qontoMsg" : "runMsg");
  if (!API_URL) { msg.textContent = "Le service de lancement n'est pas encore configuré."; return; }
  btn.disabled = true; msg.className = "hint"; msg.textContent = "Lancement… (jusqu'à 1 minute si le service était en veille)";
  try {
    const token = await getToken();
    // réveille le service (offre gratuite Render : mise en veille), puis lance
    for (let i = 0; i < 6; i++) { try { const h = await fetch(API_URL + "/health", {cache: "no-store"}); if (h.ok) break; } catch(e) {} await new Promise(r => setTimeout(r, 8000)); }
    const r = await fetch(API_URL + "/run", { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ mode }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
    msg.textContent = mode ? "Import lancé. Les factures apparaîtront ici dans quelques minutes (bouton Actualiser du suivi)." : "Traitement lancé. Le compte rendu arrivera dans Claude ; actualisez le suivi dans quelques minutes.";
    store.set("scanner.lastRun", Date.now());
  } catch(e) { msg.className = "msg"; msg.textContent = "Lancement impossible : " + (e.code === "signed_out" ? "reconnectez-vous." : e instanceof TypeError ? "le service de lancement ne répond pas (" + API_URL + "). Réessayez dans une minute." : e.message); }
  finally { setTimeout(() => { btn.disabled = false; }, 30000); }
}
$("runNow").onclick = () => runNow();
$("qontoImport").onclick = () => runNow("qonto");

/* ---------- Rendu ---------- */
function fmtSize(n){ return n > 1048576 ? (n / 1048576).toFixed(1).replace(".", ",") + " Mo" : Math.max(1, Math.round(n / 1024)) + " Ko"; }
const STATUS = { queued: ["En attente", ""], processing: ["Cadrage…", "busy"], ready: ["Prêt", ""], sending: ["Envoi…", "busy"], sent: ["Envoyé", "ok"], error: ["À corriger", "err"] };

function render(){
  renderTracking(); renderQonto();
  renderDest(); renderAccount(); $("signinBox").hidden = auth.signedIn;
  const q = $("queue");
  q.textContent = "";
  if (!items.length) {
    q.innerHTML = '<div class="empty"><svg viewBox="0 0 40 52" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 2h24l8 8v40H4z"/><path d="M28 2v8h8M10 20h20M10 27h20M10 34h12M10 42h8"/><path d="M24 42h6" stroke-width="2.2"/></svg><div>Aucun document pour l\'instant. Prenez une photo d\'un ticket ou d\'une facture, ou importez des fichiers. Les photos sont recadrées et redressées automatiquement ; vous pouvez ajuster avant l\'envoi.</div></div>';
  }
  for (const it of items) {
    const el = document.createElement("div"); el.className = "item";
    let th;
    if (it.thumb) { th = document.createElement("img"); th.className = "thumb"; th.src = it.thumb; th.alt = "Aperçu"; }
    else { th = document.createElement("div"); th.className = "thumb pdf"; th.textContent = it.kind === "pdf" ? "PDF" : "…"; }
    el.append(th);
    const m = document.createElement("div"); m.className = "meta";
    const nm = document.createElement("div"); nm.className = "name";
    const inp = document.createElement("input"); inp.id = "name-" + it.id; inp.value = it.base; inp.setAttribute("aria-label", "Nom du fichier");
    inp.disabled = it.status === "sent" || it.status === "sending";
    inp.oninput = () => { it.base = inp.value.replace(/[\\/:*?"<>|#%]/g, "-"); };
    const ext = document.createElement("span"); ext.textContent = it.status === "processing" || it.status === "queued" ? "" : extOf(it);
    nm.append(inp, ext); m.append(nm);
    const row = document.createElement("div"); row.className = "row";
    const [lbl, cls] = STATUS[it.status];
    const pill = document.createElement("span"); pill.className = "pill " + cls; pill.textContent = lbl; row.append(pill);
    if (it.out && it.status !== "processing") { const s = document.createElement("span"); s.className = "pill"; s.textContent = fmtSize(it.out.size); row.append(s); }
    if (it.kind === "image" && it.status !== "processing") {
      if (it.auto === null && it.corners && it.status !== "queued") { const s = document.createElement("span"); s.className = "pill warn"; s.textContent = "Bords non trouvés"; row.append(s); }
    }
    m.append(row);
    if (it.status === "sent") { const d = document.createElement("div"); d.className = "hint"; d.textContent = "Dans " + it.sentTo + (it.sentName ? " sous le nom " + it.sentName : ""); m.append(d);
      if (it.webUrl) { const a = document.createElement("a"); a.href = it.webUrl; a.target = "_blank"; a.rel = "noopener"; a.textContent = "Ouvrir dans OneDrive"; a.className = "hint"; a.style.color = "var(--accent)"; m.append(a); } }
    if (it.msg) { const d = document.createElement("div"); d.className = "msg"; d.textContent = it.msg; m.append(d); }
    const act = document.createElement("div"); act.className = "row";
    const busy = it.status === "processing" || it.status === "sending" || sending;
    if (it.kind === "image" && it.status !== "sent") {
      act.append(mkBtn("Rogner", () => openEditor(it), busy), mkBtn("⟲", () => quickRotate(it, -90), busy, "Pivoter à gauche"), mkBtn("⟳", () => quickRotate(it, 90), busy, "Pivoter à droite"));
    }
    if (it.status !== "sent") act.append(mkBtn("Retirer", () => { items = items.filter(x => x !== it); if (it.thumb) URL.revokeObjectURL(it.thumb); render(); }, busy));
    if (act.childNodes.length) m.append(act);
    el.append(m); q.append(el);
  }
  const ready = items.filter(x => x.status === "ready" || (x.status === "error" && x.sendFailed)).length;
  const working = items.filter(x => x.status === "processing" || x.status === "queued").length;
  const sent = items.filter(x => x.status === "sent").length;
  $("qcount").textContent = items.length ? "File d'attente · " + items.length + " document" + (items.length > 1 ? "s" : "") : "File d'attente";
  $("clearDone").hidden = !sent;
  const t = $("sendTxt");
  if (sending) t.innerHTML = "Envoi en cours…";
  else if (!auth.signedIn) t.textContent = "Connectez-vous pour envoyer.";
  else if (ready) { t.innerHTML = "<b>" + ready + "</b> prêt" + (ready > 1 ? "s" : "") + " pour <b></b>"; t.querySelector("b:last-child").textContent = dest ? dest[dest.length - 1].name : "…"; }
  else if (working) t.textContent = "Préparation des documents…";
  else t.textContent = sent ? sent + " envoyé" + (sent > 1 ? "s" : "") + "." : "Aucun document à envoyer.";
  const btn = $("sendBtn"); btn.disabled = !ready || sending || !auth.signedIn || !dest;
  btn.textContent = ready ? "Envoyer (" + ready + ")" : "Envoyer";
}
function mkBtn(label, fn, disabled, aria){ const b = document.createElement("button"); b.type = "button"; b.className = "btn small"; b.textContent = label; b.disabled = !!disabled; if (aria) b.setAttribute("aria-label", aria); b.onclick = fn; return b; }
render();
boot();
