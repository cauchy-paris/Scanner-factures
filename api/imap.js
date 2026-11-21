// Client IMAP minimal pour Gmail (mot de passe d'application), sans dépendance : Node 18+.
// Sert au relais pour récupérer les pièces jointes des factures reçues par mail et poser le libellé « Facture traitée ».
"use strict";
const tls = require("tls");

const HOST = process.env.GMAIL_IMAP_HOST || "imap.gmail.com";
const PORT = +(process.env.GMAIL_IMAP_PORT || 993);
const LABEL = "Facture traitée";

// Nom de dossier/libellé en UTF-7 modifié (RFC 3501 §5.1.3)
function utf7(s){
  return String(s).replace(/&/g, "&-").replace(/[^\x20-\x7e]+/g, m => {
    const b = Buffer.alloc(m.length * 2); for (let i = 0; i < m.length; i++) b.writeUInt16BE(m.charCodeAt(i), i * 2);
    return "&" + b.toString("base64").replace(/=+$/, "").replace(/\//g, ",") + "-";
  });
}
const quote = s => '"' + String(s).replace(/[\\"]/g, m => "\\" + m) + '"';

class Imap {
  constructor(user, pass, opts = {}){ this.user = user; this.pass = pass; this.opts = opts; this.n = 0; this.buf = Buffer.alloc(0); this.waiters = []; }
  connect(){
    return new Promise((ok, ko) => {
      const s = this.opts.connect ? this.opts.connect() : tls.connect({ host: HOST, port: PORT, servername: HOST });
      this.sock = s; let greeted = false;
      const timer = setTimeout(() => { s.destroy(); ko(new Error("Gmail ne répond pas (délai dépassé).")); }, 20000);
      s.on("data", d => { this.buf = Buffer.concat([this.buf, d]); if (!greeted) { const i = this.buf.indexOf("\r\n"); if (i >= 0) { greeted = true; clearTimeout(timer); this.buf = this.buf.slice(i + 2); ok(); } } else this.pump(); });
      s.on("error", e => { clearTimeout(timer); if (!greeted) ko(new Error("Connexion à Gmail impossible : " + e.message)); this.fail(e); });
      s.on("close", () => this.fail(new Error("Connexion Gmail fermée.")));
      s.setTimeout(60000, () => { s.destroy(new Error("Gmail ne répond plus.")); });
    });
  }
  fail(e){ const w = this.waiters; this.waiters = []; for (const x of w) x.ko(e); }
  // Découpe le flux en réponses ; gère les littéraux {n}
  pump(){
    while (this.waiters.length) {
      const w = this.waiters[0];
      if (w.cont && !w.contDone) { const i = this.buf.indexOf("\r\n"); if (i < 0) return; const line = this.buf.slice(0, i).toString("latin1");
        if (line.startsWith("+")) { this.buf = this.buf.slice(i + 2); w.contDone = true; this.sock.write(w.cont); continue; } }
      // lit une ligne logique (avec littéraux)
      let pos = 0; const parts = [];
      for (;;) {
        const i = this.buf.indexOf("\r\n", pos); if (i < 0) return;
        const seg = this.buf.slice(pos, i); const m = /\{(\d+)\}$/.exec(seg.toString("latin1"));
        if (m) { const n = +m[1]; if (this.buf.length < i + 2 + n) return; parts.push(seg, Buffer.from("\r\n"), this.buf.slice(i + 2, i + 2 + n)); pos = i + 2 + n; continue; }
        parts.push(seg); pos = i + 2; break;
      }
      const line = Buffer.concat(parts); this.buf = this.buf.slice(pos);
      const head = line.slice(0, 40).toString("latin1");
      if (head.startsWith(w.tag + " ")) {
        this.waiters.shift();
        const st = head.slice(w.tag.length + 1, w.tag.length + 3);
        if (st === "OK") w.ok(w.lines); else { const e = new Error(line.toString("utf8").slice(w.tag.length + 1)); e.imap = true; w.ko(e); }
      } else if (!head.startsWith("+")) w.lines.push(line);
    }
  }
  cmd(text, literal){
    const tag = "A" + (++this.n);
    return new Promise((ok, ko) => {
      const w = { tag, lines: [], ok, ko };
      if (literal !== undefined) { const b = Buffer.from(literal, "utf8"); w.cont = Buffer.concat([b, Buffer.from("\r\n")]); this.sock.write(tag + " " + text + "{" + b.length + "}\r\n"); }
      else this.sock.write(tag + " " + text + "\r\n");
      this.waiters.push(w); this.pump();
    });
  }
  async login(){
    try { await this.cmd("LOGIN " + quote(this.user) + " " + quote(this.pass)); }
    catch (e) { throw new Error(/AUTHENTICATIONFAILED|Invalid credentials|LOGIN failed/i.test(e.message)
      ? "Gmail refuse l'adresse ou le mot de passe d'application (vérifiez-les, et que la validation en deux étapes est active)."
      : /WEBALERT|ALERT|Application-specific/i.test(e.message) ? "Gmail demande un mot de passe d'application (myaccount.google.com/apppasswords)." : "Connexion Gmail refusée : " + e.message); }
  }
  async selectAll(){
    const lines = await this.cmd('LIST "" "*"');
    let box = "[Gmail]/All Mail";
    for (const l of lines) { const s = l.toString("latin1"); if (/\\All\b/.test(s)) { const m = /"([^"]+)"\s*$/.exec(s) || /\s(\S+)\s*$/.exec(s); if (m) box = m[1]; } }
    await this.cmd("SELECT " + quote(box)); return box;
  }
  async search(raw){
    const lines = await this.cmd("UID SEARCH CHARSET UTF-8 X-GM-RAW ", raw);
    const out = []; for (const l of lines) { const m = /^\* SEARCH ?(.*)$/.exec(l.toString("latin1")); if (m) out.push(...m[1].trim().split(/\s+/).filter(Boolean).map(Number)); }
    return out;
  }
  async fetchSizes(uids){
    if (!uids.length) return [];
    const lines = await this.cmd("UID FETCH " + uids.join(",") + " (UID RFC822.SIZE X-GM-MSGID)");
    return lines.map(l => l.toString("latin1")).map(s => ({ uid: +(/UID (\d+)/.exec(s) || [])[1], size: +(/RFC822\.SIZE (\d+)/.exec(s) || [])[1], msgid: (/X-GM-MSGID (\d+)/.exec(s) || [])[1] })).filter(x => x.uid);
  }
  async fetchRaw(uid){
    const lines = await this.cmd("UID FETCH " + uid + " (BODY.PEEK[])");
    for (const l of lines) { const i = l.indexOf("}\r\n"); if (i > 0) { const n = +(/\{(\d+)\}$/.exec(l.slice(0, i + 1).toString("latin1")) || [])[1]; return l.slice(i + 3, i + 3 + n); } }
    throw new Error("Message " + uid + " illisible.");
  }
  async label(uids){ if (uids.length) await this.cmd("UID STORE " + uids.join(",") + " +X-GM-LABELS (" + quote(utf7(LABEL)) + ")"); }
  async logout(){ try { await this.cmd("LOGOUT"); } catch (e) {} try { this.sock.end(); } catch (e) {} }
}

/* ---------- MIME ---------- */
function decodeWords(s){
  return String(s || "").replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=\s*(?==\?)/g, "=?$1?$2?$3?=").replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=/g, (m, cs, enc, txt) => {
    try {
      const b = enc.toUpperCase() === "B" ? Buffer.from(txt, "base64") : Buffer.from(txt.replace(/_/g, " ").replace(/=([0-9a-f]{2})/gi, (x, h) => String.fromCharCode(parseInt(h, 16))), "latin1");
      return new TextDecoder(/^(utf-?8|iso-8859-1|latin1|windows-1252|us-ascii)$/i.test(cs) ? cs : "utf-8").decode(b);
    } catch (e) { return m; }
  });
}
function parseHeaders(txt){
  const h = {}; for (const line of txt.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/)) { const i = line.indexOf(":"); if (i > 0) { const k = line.slice(0, i).trim().toLowerCase(); if (!(k in h)) h[k] = line.slice(i + 1).trim(); } }
  return h;
}
function param(v, name){
  v = String(v || "");
  const star = new RegExp(";\\s*" + name + "\\*(?:0\\*?)?=([^;]+)", "i").exec(v);
  if (star) { let s = star[1].trim().replace(/^"|"$/g, ""); const m = /^([^']*)'[^']*'(.*)$/.exec(s);
    // suites RFC 2231 (name*0*, name*1*…)
    const more = []; const re = new RegExp(";\\s*" + name + "\\*(\\d+)\\*?=([^;]+)", "ig"); let x; while ((x = re.exec(v))) if (+x[1] > 0) more[+x[1]] = x[2].trim().replace(/^"|"$/g, "");
    s = (m ? m[2] : s) + more.filter(Boolean).join("");
    try { return decodeURIComponent(s); } catch (e) { return s; } }
  const m = new RegExp(";\\s*" + name + '=("([^"]*)"|[^;]+)', "i").exec(v);
  return m ? decodeWords((m[2] !== undefined ? m[2] : m[1]).trim()) : "";
}
function decodeBody(buf, enc){
  enc = String(enc || "").toLowerCase();
  if (enc === "base64") return Buffer.from(buf.toString("latin1").replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
  if (enc === "quoted-printable") return Buffer.from(buf.toString("latin1").replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))), "latin1");
  return buf;
}
// Renvoie { headers, attachments: [{ name, type, data }] }
function parseMessage(raw, out){
  out = out || { attachments: [] };
  const sep = raw.indexOf("\r\n\r\n") >= 0 ? raw.indexOf("\r\n\r\n") : raw.indexOf("\n\n");
  const headTxt = raw.slice(0, sep < 0 ? raw.length : sep).toString("utf8"), body = sep < 0 ? Buffer.alloc(0) : raw.slice(sep + (raw[sep] === 13 ? 4 : 2));
  const h = parseHeaders(headTxt); if (!out.headers) out.headers = h;
  const ct = h["content-type"] || "text/plain", type = ct.split(";")[0].trim().toLowerCase();
  if (type.startsWith("multipart/")) {
    const b = param(ct, "boundary"); if (!b) return out;
    const delim = Buffer.from("--" + b); let i = body.indexOf(delim);
    while (i >= 0) {
      let start = body.indexOf("\n", i) + 1; if (start <= 0) break;
      if (body.slice(i + delim.length, i + delim.length + 2).toString() === "--") break;
      const j = body.indexOf(delim, start); const end = j < 0 ? body.length : j;
      let part = body.slice(start, end); if (part.slice(-2).toString() === "\r\n") part = part.slice(0, -2); else if (part.slice(-1).toString() === "\n") part = part.slice(0, -1);
      parseMessage(part, out); i = j;
    }
    return out;
  }
  if (type === "message/rfc822") return parseMessage(decodeBody(body, h["content-transfer-encoding"]), out);
  const disp = h["content-disposition"] || "";
  const name = param(disp, "filename") || param(ct, "name");
  if (name && !/^text\//.test(type)) out.attachments.push({ name, type, data: decodeBody(body, h["content-transfer-encoding"]), inline: /^inline/i.test(disp) || !!h["content-id"] });
  return out;
}
function kindOf(a){
  const n = a.name.toLowerCase();
  if (a.type === "application/pdf" || n.endsWith(".pdf")) return "application/pdf";
  if (/^image\/jpe?g$/.test(a.type) || /\.jpe?g$/.test(n)) return "image/jpeg";
  if (a.type === "image/png" || n.endsWith(".png")) return "image/png";
  return "";
}

/* ---------- Opérations du relais ---------- */
async function session(user, pass, fn, opts){
  const c = new Imap(user, pass, opts); await c.connect();
  try { await c.login(); return await fn(c); } finally { await c.logout(); }
}
/* ---------- Tri strict : ne garder que les factures ----------
   Une pièce jointe est retenue seulement si rien n'indique un autre document (CGV, publicité, garantie,
   relevé, devis…) ET si son nom ou l'objet du mail indique une facture. Le reste est « écarté » avec un motif. */
function plain(s){ return String(s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[_\-.+]+/g, " ").replace(/\s+/g, " "); }
function prettyName(n){
  if (!/%[0-9A-Fa-f]{2}/.test(n)) return n;
  try { return decodeURIComponent(n); } catch(e) { return n.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))); }
}
const NOT_INVOICE = [
  [/conditions? (generales?|particulieres?|de vente|d utilisation)|\bc ?g ?[vua]\b/, "conditions générales"],
  [/retractation/, "formulaire de rétractation"], [/garantie/, "garantie"], [/mentions? legales?|rgpd|confidentialite|cookies?/, "mentions légales"],
  [/fiche (informative|technique|produit)|brochure|catalogue|plaquette|newsletter|lettre d info|actualites?|publicite|promo(tion)?s?\b|offres?\b|flyer|invitation|webinaire/, "information ou publicité"],
  [/notice|guide|mode d emploi|tutoriel|presentation/, "notice ou guide"], [/tarifs?\b|grille tarifaire|devis|proposition commerciale/, "devis ou tarif"],
  [/bon de (commande|livraison)|confirmation de commande|accuse de reception|bordereau/, "bon de commande ou de livraison"],
  [/releve|situation de compte|echeancier|lettre de relance|relance/, "relevé ou relance"],
  [/contrat|avenant|attestation|kbis|\brib\b|\biban\b|statuts|proces verbal|\bcv\b/, "document administratif"],
];
const INVOICE_NAME = /factur|invoice|\bavoir|credit note|receipt|\brecu\b|ticket|quittance|note (de frais|d honoraires)|duplicata|(^|\s)(f|fa|fac|fct|inv|in)\s?\d{3,}/;
const INVOICE_SUBJECT = /factur|invoice|\bavoir|receipt|\brecu\b|ticket de caisse|quittance|note d honoraires|justificatif de paiement/;
function classify(name, subject){
  const n = plain(name), s = plain(subject);
  for (const [re, why] of NOT_INVOICE) if (re.test(n)) return { ok: false, motif: "pas une facture (" + why + ")" };
  if (INVOICE_NAME.test(n)) return { ok: true };
  if (INVOICE_SUBJECT.test(s)) {
    for (const [re, why] of NOT_INVOICE) if (re.test(s)) return { ok: false, motif: "mail « " + why + " » sans pièce nommée facture" };
    return { ok: true };
  }
  return { ok: false, motif: "aucun indice de facture dans le nom du fichier ni l'objet du mail" };
}
const QUERY = d => 'has:attachment -from:me -label:"' + LABEL + '" newer_than:' + d + "d (facture OR invoice OR receipt OR reçu OR avoir OR quittance OR \"ticket de caisse\" OR \"note d'honoraires\")";
// Messages non traités, avec leurs pièces jointes utiles (PDF, et images hors logos de signature)
async function fetchInvoices(user, pass, { days = 30, skip = [], max = 8, maxBytes = 20 * 1024 * 1024 } = {}, opts){
  return session(user, pass, async c => {
    await c.selectAll();
    const uids = (await c.search(QUERY(Math.max(1, Math.min(365, days | 0))))).sort((a, b) => b - a);
    const info = (await c.fetchSizes(uids.slice(0, 200))).filter(x => !skip.includes(x.msgid));
    const messages = [], skipped = []; let total = 0;
    for (const m of info) {
      if (messages.length >= max) break;
      if (m.size > maxBytes || total + m.size > 30 * 1024 * 1024) { skipped.push({ msgid: m.msgid, uid: m.uid, size: m.size }); continue; }
      const p = parseMessage(await c.fetchRaw(m.uid)); total += m.size;
      const subject = decodeWords(p.headers.subject || ""), files = [], ecartes = [];
      for (const a of p.attachments.map(a => ({ ...a, name: prettyName(a.name), type: kindOf(a) })).filter(a => a.type && (a.type === "application/pdf" || (!a.inline && a.data.length > 15000)))) {
        const c = classify(a.name, subject);
        const hash = require("crypto").createHash("sha256").update(a.data).digest("hex").slice(0, 24);   // empreinte : évite de réimporter le même document reçu dans un autre mail
        if (c.ok) files.push({ name: a.name, type: a.type, size: a.data.length, hash, data: a.data.toString("base64") });
        else ecartes.push({ nom: a.name, motif: c.motif, hash });
      }
      messages.push({ uid: m.uid, msgid: m.msgid, subject, from: decodeWords(p.headers.from || ""), date: p.headers.date || "", attachments: files, ecartes });
    }
    return { messages, more: info.length > messages.length + skipped.length, skipped, found: info.length };
  }, opts);
}
async function labelDone(user, pass, uids, opts){ return session(user, pass, async c => { await c.selectAll(); await c.label(uids.map(Number).filter(n => n > 0)); return { ok: true }; }, opts); }
async function test(user, pass, opts){ return session(user, pass, async c => { const box = await c.selectAll(); return { ok: true, box }; }, opts); }

module.exports = { fetchInvoices, labelDone, test, parseMessage, utf7, Imap, QUERY, classify, prettyName };
