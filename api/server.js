// Service de lancement : reçoit la demande de l'appli, vérifie le compte Microsoft
// de l'utilisateur, puis déclenche la tâche planifiée Claude « Traitement des factures ».
// Aucune dépendance : Node 18+.
const http = require("http");

const PORT = process.env.PORT || 10000;
const ROUTINE_ID = process.env.ROUTINE_ID || "";
const ROUTINE_TOKEN = process.env.ROUTINE_TOKEN || "";
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || "").toLowerCase().split(/[,\s]+/).filter(Boolean);
const MIN_INTERVAL_MS = +(process.env.MIN_INTERVAL_MS || 120000);
const QONTO_LOGIN = process.env.QONTO_LOGIN || "";
const QONTO_SECRET_KEY = process.env.QONTO_SECRET_KEY || "";
const QONTO_API = "https://thirdparty.qonto.com/v2";

// Noms de fournisseurs normalisés (identiques à ceux du tableau des dépenses)
const SUPPLIERS = [[/leroy\s*merlin/i, "LEROY MERLIN"], [/castorama/i, "CASTORAMA"], [/schmitt\s*ney/i, "SCHMITTNEY"],
  [/loxam/i, "LOXAM"], [/radiot|\bsfr\b/i, "SFR"], [/^qonto\b/i, "QONTO"], [/chadapaux/i, "CHADAPAUX"]];
function supplierName(raw){
  raw = String(raw || "").trim();
  for (const [re, n] of SUPPLIERS) if (re.test(raw)) return n;
  return raw.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase()
    .replace(/\b(S\.?A\.?S\.?U?|S\.?A\.?R\.?L\.?|S\.?A\.?|EURL|SASU)\b\.?/g, "")
    .replace(/[\\/:*?"<>|#%]+/g, " ").replace(/\s+/g, " ").trim() || "FOURNISSEUR";
}
const money = v => +((v && v.value) || 0);
const fr = n => n.toFixed(2).replace(".", ",");

async function qonto(path){
  const r = await fetch(QONTO_API + path, { headers: { Authorization: QONTO_LOGIN + ":" + QONTO_SECRET_KEY, Accept: "application/json" } });
  if (!r.ok) { const e = new Error("Qonto a répondu " + r.status + "."); e.status = r.status; throw e; }
  return r.json();
}

// Toutes les factures électroniques fournisseurs (source e_invoicing), au format attendu par l'appli
async function listEinvoices(){
  const out = [];
  for (let page = 1; page && page < 50; ) {
    const j = await qonto("/supplier_invoices?per_page=100&page=" + page);
    for (const x of j.supplier_invoices || []) {
      if (x.source !== "e_invoicing" && !x.is_einvoice) continue;
      const sign = x.is_credit_note ? -1 : 1;
      const ttc = sign * Math.abs(money(x.total_amount));
      const tva = sign * Math.abs(money(x.total_tax_amount));
      const ht = x.total_amount_excluding_taxes ? sign * Math.abs(money(x.total_amount_excluding_taxes)) : +(ttc - tva).toFixed(2);
      const date = String(x.issue_date || x.created_at || "").slice(0, 10);
      const sup = supplierName(x.supplier_name || (x.seller && x.seller.name));
      out.push({ id: x.id, supplier: sup, supplierRaw: x.supplier_name || "", number: x.invoice_number || "", date,
        ht, tva, ttc, creditNote: !!x.is_credit_note, status: x.status || "",
        attachmentId: x.display_attachment_id || x.attachment_id || "",
        transactions: (x.matched_transactions || []).map(t => t.transaction_id || t.subject_id).filter(Boolean),
        fileName: date.replace(/-/g, "") + "_" + sup + "_" + fr(ttc) + "€TTC.pdf" });
    }
    page = j.meta && j.meta.next_page;
  }
  // deux factures identiques (même jour, fournisseur, montant) : on distingue par le numéro
  const seen = {};
  for (const f of out) seen[f.fileName] = (seen[f.fileName] || 0) + 1;
  for (const f of out) if (seen[f.fileName] > 1) f.fileName = f.fileName.replace(/\.pdf$/, "_" + String(f.number).replace(/[^\w-]+/g, "") + ".pdf");
  return out;
}

let lastRun = 0;

function send(res, origin, status, body){
  const h = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
  // CORS ouvert : la sécurité repose sur le jeton Microsoft vérifié ci-dessous, pas sur l'origine
  if (origin) {
    h["Access-Control-Allow-Origin"] = origin; h["Vary"] = "Origin";
    h["Access-Control-Allow-Headers"] = "Authorization, Content-Type"; h["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"; h["Access-Control-Max-Age"] = "600";
  }
  res.writeHead(status, h); res.end(body === undefined ? "" : JSON.stringify(body));
}

// Vérifie l'utilisateur avec son jeton Microsoft (appel Graph /me) ; renvoie un message d'erreur ou ""
async function checkUser(req){
  const auth = req.headers.authorization || "";
  if (!/^Bearer \S+$/.test(auth)) return [401, "Connexion Microsoft requise."];
  let me;
  try {
    const r = await fetch("https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName", { headers: { Authorization: auth } });
    if (!r.ok) return [401, "Session Microsoft invalide ou expirée."];
    me = await r.json();
  } catch (e) { return [502, "Microsoft injoignable."]; }
  const who = [me.mail, me.userPrincipalName].filter(Boolean).map(s => s.toLowerCase());
  if (!who.some(w => ALLOWED_EMAILS.includes(w))) return [403, "Ce compte n'est pas autorisé."];
  return null;
}

http.createServer(async (req, res) => {
  const origin = req.headers.origin || "";
  const url = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") return send(res, origin, 204);
  if (req.method === "GET" && url.pathname === "/health") return send(res, origin, 200, { ok: true });
  if (req.method === "GET" && url.pathname.startsWith("/qonto/")) {
    if (!ALLOWED_EMAILS.length) return send(res, origin, 500, { error: "Service non configuré (ALLOWED_EMAILS)." });
    if (!QONTO_LOGIN || !QONTO_SECRET_KEY) return send(res, origin, 501, { error: "Clé API Qonto absente : ajoutez QONTO_LOGIN et QONTO_SECRET_KEY dans Render." });
    const bad = await checkUser(req); if (bad) return send(res, origin, bad[0], { error: bad[1] });
    try {
      if (url.pathname === "/qonto/einvoices") return send(res, origin, 200, { invoices: await listEinvoices() });
      if (url.pathname === "/qonto/pdf") {
        const id = url.searchParams.get("attachment") || "";
        if (!/^[0-9a-f-]{36}$/i.test(id)) return send(res, origin, 400, { error: "Pièce jointe invalide." });
        const a = (await qonto("/attachments/" + id)).attachment || {};
        if (!a.url) return send(res, origin, 404, { error: "PDF introuvable dans Qonto." });
        const f = await fetch(a.url);
        if (!f.ok) return send(res, origin, 502, { error: "Téléchargement Qonto impossible (" + f.status + ")." });
        const buf = Buffer.from(await f.arrayBuffer());
        res.writeHead(200, { "Content-Type": a.file_content_type || "application/pdf", "Content-Length": buf.length, "Cache-Control": "no-store",
          ...(origin ? { "Access-Control-Allow-Origin": origin, "Vary": "Origin" } : {}) });
        return res.end(buf);
      }
      return send(res, origin, 404, { error: "Introuvable" });
    } catch (e) { return send(res, origin, 502, { error: e.status === 401 ? "Clé API Qonto refusée : vérifiez QONTO_LOGIN et QONTO_SECRET_KEY." : (e.message || "Qonto injoignable.") }); }
  }
  if (req.method !== "POST" || url.pathname !== "/run") return send(res, origin, 404, { error: "Introuvable" });
  if (!ROUTINE_ID || !ROUTINE_TOKEN || !ALLOWED_EMAILS.length) return send(res, origin, 500, { error: "Service non configuré (ROUTINE_ID, ROUTINE_TOKEN, ALLOWED_EMAILS)." });

  // 1. vérifie l'utilisateur avec son jeton Microsoft
  const bad = await checkUser(req); if (bad) return send(res, origin, bad[0], { error: bad[1] });

  // 2. anti-rafale
  const now = Date.now();
  if (now - lastRun < MIN_INTERVAL_MS) return send(res, origin, 429, { error: "Un traitement vient d'être lancé. Réessayez dans " + Math.ceil((MIN_INTERVAL_MS - (now - lastRun)) / 1000) + " s." });

  // 3. type de lancement : traitement normal, ou import de toutes les e-factures Qonto
  let mode = "", report = "";
  try {
    let raw = ""; for await (const c of req) { raw += c; if (raw.length > 4000) break; }
    const b = raw ? (JSON.parse(raw) || {}) : {};
    mode = String(b.mode || ""); report = String(b.report || "").replace(/[\r\n]+/g, " ").slice(0, 1500);
  } catch (e) { mode = ""; }
  const text = (mode === "qonto"
    ? "Lancement manuel depuis l'appli Scanner de factures : Importer les factures Qonto (toutes les factures électroniques fournisseurs depuis le 01/01/2026, §2 bis de la procédure, avec anti-doublon). L'appli vient de ranger les PDF dans Fournisseurs/<NOM>/<AAAA> : mets le lien « justificatif » des lignes d'après _Automatisation/efactures_classees.json. Puis le traitement habituel."
    : "Lancement manuel depuis l'appli Scanner de factures.")
    + (report ? " Résultat de l'import côté appli (à recopier tel quel dans le compte rendu) : " + report : "");

  // 4. déclenche la tâche planifiée
  try {
    const r = await fetch("https://api.anthropic.com/v1/claude_code/routines/" + encodeURIComponent(ROUTINE_ID) + "/fire", {
      method: "POST",
      headers: { Authorization: "Bearer " + ROUTINE_TOKEN, "anthropic-beta": "experimental-cc-routine-2026-04-01",
        "anthropic-version": "2023-06-01", "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return send(res, origin, 502, { error: "Claude a refusé le lancement (" + r.status + ")." + (j.error && j.error.message ? " " + j.error.message : "") });
    lastRun = now;
    return send(res, origin, 200, { ok: true, session_url: j.claude_code_session_url || "" });
  } catch (e) { return send(res, origin, 502, { error: "Claude injoignable." }); }
}).listen(PORT, () => console.log("Service de lancement prêt sur le port " + PORT));
