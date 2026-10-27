// Runs ui_audit.js on every view and Settings tab, in dark and light, at the
// current window width. Inject ui_audit.js as `window.__uiAudit = () => <its
// expression>` first (tests/dashboard/inject_audit.py prints the combined
// script), then evaluate this file; it resolves to a list of every view
// whose audit total is not 0, plus a per-view count.
//
// Set the width with the browser tool (1600, 1282, 1024, 375) and run again.
// The sweep restores the theme and view it started from.
(async () => {
  const ROUTES = ['overview', 'live', 'events', 'alerts', 'controls', 'policy', 'labels', 'labels?view=confirmed', 'labels?view=history', 'ai', 'audit',
    'settings?tab=ai', 'settings?tab=challenge', 'settings?tab=users', 'settings?tab=storage', 'settings?tab=geo', 'settings?tab=pages', 'settings?tab=security'];
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  // A view is ready when it has no skeleton rows or loading boxes left.
  const settled = async () => {
    for (let i = 0; i < 40; i++) {
      await wait(150);
      if (!document.querySelector('#view .skeleton, #view .sk, #view [aria-busy=true]')) return;
    }
  };
  const root = document.documentElement;
  const startTheme = root.dataset.theme;
  const startHash = location.hash;
  const failures = [];
  const totals = {};
  for (const route of ROUTES) {
    location.hash = '#/' + route;
    await settled();
    await wait(400);
    for (const theme of ['dark', 'light']) {
      root.dataset.theme = theme;
      window.dispatchEvent(new Event('os-theme'));
      await wait(250);
      const r = window.__uiAudit();
      totals[route + ' ' + theme] = r.total;
      if (r.total) {
        const keep = {};
        for (const [k, v] of Object.entries(r)) {
          if (['view', 'theme', 'width', 'total', 'scrollsX'].includes(k)) continue;
          if (Array.isArray(v) ? v.length : (v && typeof v === 'object' ? Object.keys(v).length : v)) keep[k] = v;
        }
        failures.push({ route, theme, width: innerWidth, total: r.total, ...keep });
      }
    }
  }
  if (startTheme) root.dataset.theme = startTheme; else delete root.dataset.theme;
  window.dispatchEvent(new Event('os-theme'));
  location.hash = startHash;
  return { width: innerWidth, totals, failures };
})();
