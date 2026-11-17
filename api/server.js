// Service de lancement : reçoit la demande de l'appli, vérifie le compte Microsoft
// de l'utilisateur, puis déclenche la tâche planifiée Claude « Traitement des factures ».
// Aucune dépendance : Node 18+.
const http = require("http");

const PORT = process.env.PORT || 10000;
const ROUTINE_ID = process.env.ROUTINE_ID || "";
const ROUTINE_TOKEN = process.env.ROUTINE_TOKEN || "";
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || "").toLowerCase().split(/[,\s]+/).filter(Boolean);
const MIN_INTERVAL_MS = +(process.env.MIN_INTERVAL_MS || 120000);

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

http.createServer(async (req, res) => {
  const origin = req.headers.origin || "";
  const url = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") return send(res, origin, 204);
  if (req.method === "GET" && url.pathname === "/health") return send(res, origin, 200, { ok: true });
  if (req.method !== "POST" || url.pathname !== "/run") return send(res, origin, 404, { error: "Introuvable" });
  if (!ROUTINE_ID || !ROUTINE_TOKEN || !ALLOWED_EMAILS.length) return send(res, origin, 500, { error: "Service non configuré (ROUTINE_ID, ROUTINE_TOKEN, ALLOWED_EMAILS)." });

  // 1. vérifie l'utilisateur avec son jeton Microsoft (appel Graph /me)
  const auth = req.headers.authorization || "";
  if (!/^Bearer \S+$/.test(auth)) return send(res, origin, 401, { error: "Connexion Microsoft requise." });
  let me;
  try {
    const r = await fetch("https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName", { headers: { Authorization: auth } });
    if (!r.ok) return send(res, origin, 401, { error: "Session Microsoft invalide ou expirée." });
    me = await r.json();
  } catch (e) { return send(res, origin, 502, { error: "Microsoft injoignable." }); }
  const who = [me.mail, me.userPrincipalName].filter(Boolean).map(s => s.toLowerCase());
  if (!who.some(w => ALLOWED_EMAILS.includes(w))) return send(res, origin, 403, { error: "Ce compte n'est pas autorisé à lancer le traitement." });

  // 2. anti-rafale
  const now = Date.now();
  if (now - lastRun < MIN_INTERVAL_MS) return send(res, origin, 429, { error: "Un traitement vient d'être lancé. Réessayez dans " + Math.ceil((MIN_INTERVAL_MS - (now - lastRun)) / 1000) + " s." });

  // 3. type de lancement : traitement normal, ou import de toutes les e-factures Qonto
  let mode = "";
  try {
    let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) break; }
    mode = raw ? String((JSON.parse(raw) || {}).mode || "") : "";
  } catch (e) { mode = ""; }
  const text = mode === "qonto"
    ? "Lancement manuel depuis l'appli Scanner de factures : Importer les factures Qonto (toutes les factures électroniques fournisseurs depuis le 01/01/2026, §2 bis de la procédure, avec anti-doublon), puis le traitement habituel."
    : "Lancement manuel depuis l'appli Scanner de factures.";

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
