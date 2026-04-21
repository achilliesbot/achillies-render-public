// ============================================================
// === AGENTIAM LANDING PAGE — served at /agentiam ===
// ADD-ONLY. No existing route modified.
// ============================================================
const __agentiamHtmlPath = join(dirname(fileURLToPath(import.meta.url)), 'agentiam-landing.html');
let __agentiamHtmlCache = null;
function __getAgentiamHtml() {
  if (__agentiamHtmlCache) return __agentiamHtmlCache;
  try { __agentiamHtmlCache = readFileSync(__agentiamHtmlPath, 'utf8'); } catch { __agentiamHtmlCache = '<h1>AgentIAM</h1>'; }
  return __agentiamHtmlCache;
}
app.get('/agentiam', (req, res) => {
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.set('Cache-Control', 'public, max-age=300');
  res.send(__getAgentiamHtml());
});
app.get('/agentiam/', (req, res) => res.redirect(301, '/agentiam'));

