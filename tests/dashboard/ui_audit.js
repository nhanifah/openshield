// Visual consistency audit for the dashboard. Paste into the browser
// console (or run through a browser automation tool) on any view; it
// returns a report of anomalies. Run it on every view, in both themes and
// at phone width, before shipping UI changes (see CLAUDE.md).
(() => {
  const vis = (el) => {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && !el.closest('[hidden]');
  };
  const name = (el) => {
    const parts = [];
    for (let n = el, i = 0; n && n.nodeType === 1 && i < 4; n = n.parentElement, i++) {
      let p = n.tagName.toLowerCase();
      if (n.id) { p += '#' + n.id; parts.unshift(p); break; }
      const cls = [...n.classList].slice(0, 2).join('.');
      if (cls) p += '.' + cls;
      parts.unshift(p);
    }
    const t = (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 30);
    return parts.join(' > ') + (t ? ' "' + t + '"' : '');
  };
  const all = [...document.querySelectorAll('#app *, #login *, dialog[open] *')].filter(vis);
  const out = { view: location.hash, theme: document.documentElement.dataset.theme || 'system', width: innerWidth };

  // 1. Struck-through text reads as broken or disabled.
  out.strike = all.filter((el) => getComputedStyle(el).textDecorationLine.includes('line-through')).map(name);

  // 2. Pills inside pills (double borders).
  const PILL = '.badge, .chip, .chip-toggle, .pill';
  out.nestedPills = all.filter((el) => el.matches(PILL) && el.parentElement && el.parentElement.closest(PILL)).map(name);

  // 3. Controls side by side in one row must share a height.
  const CTRL = 'button, input:not([type=checkbox]):not([type=radio]), select, a.btn, .seg';
  const rows = new Map();
  for (const el of all.filter((e) => e.matches(CTRL) && !e.closest('.seg button') && !e.closest('td') && !e.closest('.chip'))) {
    const parent = el.parentElement;
    const cs = getComputedStyle(parent);
    if (!cs.display.includes('flex') || cs.flexDirection.startsWith('column')) continue;
    if (el.matches('.btn-link, .btn-icon') || el.closest('.seg') && !el.matches('.seg')) continue;
    if (!rows.has(parent)) rows.set(parent, []);
    rows.get(parent).push(el);
  }
  out.rowHeights = [];
  for (const [parent, ctrls] of rows) {
    if (ctrls.length < 2) continue;
    const hs = ctrls.map((c) => Math.round(c.getBoundingClientRect().height));
    if (Math.max(...hs) - Math.min(...hs) > 2) out.rowHeights.push(name(parent) + ' heights=' + hs.join('/'));
  }

  // 4. Content spilling out of its box, or past the viewport. Content inside
  // a box that scrolls sideways on purpose (wide data tables) is listed as
  // info in scrollsX instead.
  const scrollsX = (n) => ['auto', 'scroll'].includes(getComputedStyle(n).overflowX);
  out.scrollsX = all.filter((el) => scrollsX(el) && el.scrollWidth > el.clientWidth + 1).map(name);
  out.overflow = all.filter((el) => {
    const cs = getComputedStyle(el);
    if (['auto', 'scroll', 'hidden', 'clip'].includes(cs.overflowX) || el.matches('textarea, pre, input, select')) return false;
    for (let n = el.parentElement; n && n !== document.body; n = n.parentElement) if (scrollsX(n)) return false;
    const r = el.getBoundingClientRect();
    return el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0 || r.right > innerWidth + 1;
  }).slice(0, 15).map(name);
  out.pageScrollsSideways = document.documentElement.scrollWidth > innerWidth + 1;

  // 4b. Badges and buttons cut off by a box that hides overflow (table cells
  // hide it, so check 4 cannot see these).
  out.clippedControls = all.filter((el) => el.matches('.badge, .btn, .chip-toggle, .chip')).filter((el) => {
    const r = el.getBoundingClientRect();
    for (let n = el.parentElement; n && n !== document.body; n = n.parentElement) {
      const ox = getComputedStyle(n).overflowX;
      if (ox === 'auto' || ox === 'scroll') return false;
      if (ox === 'hidden' || ox === 'clip') { const c = n.getBoundingClientRect(), cs = getComputedStyle(n); return r.right > c.right - parseFloat(cs.paddingRight) + 0.5 || r.left < c.left + parseFloat(cs.paddingLeft) - 0.5; }
    }
    return false;
  }).slice(0, 10).map(name);

  // 5. Text cut off vertically inside a fixed box.
  out.clippedText = all.filter((el) => {
    const cs = getComputedStyle(el);
    return (cs.overflowY === 'hidden' || cs.overflow === 'hidden') && el.scrollHeight > el.clientHeight + 2 && el.textContent.trim() && !el.matches('.card, .table-wrap, .drawer, .live-wrap, .sr-only');
  }).slice(0, 10).map(name);

  // 6. Containers of one kind must share radius and padding.
  out.containerStyles = {};
  for (const sel of ['.card', '.kpi', '.status-strip', '.callout', '.verdict', '.chip-toggle', '.badge', '.btn:not(.btn-sm):not(.btn-icon):not(.btn-link)', '.btn-sm', 'input[type=text]', 'select']) {
    const vals = new Set(all.filter((el) => el.matches(sel)).map((el) => {
      const cs = getComputedStyle(el);
      // Height is compared only for controls; containers grow with content.
      const hgt = el.matches('.card, .callout, .verdict, .status-strip') ? '' : ` h=${Math.round(el.getBoundingClientRect().height)}`;
      return `r=${cs.borderRadius} pad=${cs.paddingTop}/${cs.paddingLeft}${hgt}`;
    }));
    if (vals.size > 1) out.containerStyles[sel] = [...vals];
  }

  // 6b. Cards side by side in one grid row must share a height.
  out.uneven = [];
  for (const g of all.filter((el) => getComputedStyle(el).display === 'grid')) {
    const rowsByTop = new Map();
    for (const c of [...g.children].filter((c) => c.matches('.card, .kpi, .stat') && vis(c))) {
      const top = Math.round(c.getBoundingClientRect().top);
      if (!rowsByTop.has(top)) rowsByTop.set(top, []);
      rowsByTop.get(top).push(Math.round(c.getBoundingClientRect().height));
    }
    for (const hs of rowsByTop.values()) if (hs.length > 1 && Math.max(...hs) - Math.min(...hs) > 2) out.uneven.push(name(g) + ' heights=' + hs.join('/'));
  }

  // 7. WCAG contrast of visible text (4.5:1, or 3:1 for large text).
  // Any CSS color (rgb, color(srgb ...), and the oklab()/oklch() values
  // Chrome reports mid-animation) is resolved by painting it on a canvas.
  const px = document.createElement('canvas').getContext('2d', { willReadFrequently: true });
  const parsed = new Map();
  const parse = (c) => {
    if (parsed.has(c)) return parsed.get(c);
    px.clearRect(0, 0, 1, 1);
    px.fillStyle = 'rgba(0, 0, 0, 0)';
    px.fillStyle = c;
    px.fillRect(0, 0, 1, 1);
    const [r, g, b, a] = px.getImageData(0, 0, 1, 1).data;
    const v = [r, g, b, a / 255];
    parsed.set(c, v);
    return v;
  };
  const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
  const bgOf = (el) => {
    const layers = [];
    for (let n = el; n; n = n.parentElement) {
      const c = parse(getComputedStyle(n).backgroundColor);
      const a = c.length > 3 ? c[3] : 1;
      if (a > 0) layers.push([c[0], c[1], c[2], a]);
      if (a >= 1) break;
    }
    let col = [255, 255, 255];
    for (const [r, g, b, a] of layers.reverse()) col = [r * a + col[0] * (1 - a), g * a + col[1] * (1 - a), b * a + col[2] * (1 - a)];
    return col;
  };
  const low = [];
  for (const el of all) {
    if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
    const cs = getComputedStyle(el);
    if (parseFloat(cs.opacity) < 1 || el.closest(':disabled, [aria-disabled=true]')) continue;
    const fg = parse(cs.color), bg = bgOf(el);
    const a = fg.length > 3 ? fg[3] : 1;
    const f = [fg[0] * a + bg[0] * (1 - a), fg[1] * a + bg[1] * (1 - a), fg[2] * a + bg[2] * (1 - a)];
    const L1 = lum(f), L2 = lum(bg);
    const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
    const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight, 10) >= 700;
    const need = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
    if (ratio < need) low.push(ratio.toFixed(2) + ' < ' + need + ' ' + name(el));
  }
  out.lowContrast = low.slice(0, 15);
  out.lowContrastCount = low.length;

  // 8. Small tap targets at phone width. A checkbox's target is its label row.
  const target = (el) => (el.matches('input[type=checkbox], input[type=radio]') && el.closest('label')) || el;
  out.smallTargets = innerWidth < 760
    ? all.filter((el) => el.matches('button, a[href], input, select') && target(el).getBoundingClientRect().height < 32 && !el.closest('td')).slice(0, 12).map((el) => Math.round(el.getBoundingClientRect().height) + 'px ' + name(el))
    : [];

  // 9. Keyboard stops nobody can see: focusable controls placed beside the
  // viewport (a closed slide-in menu) that are not inside a sideways scroller.
  const FOCUSABLE = 'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';
  out.offscreenFocusable = [...document.querySelectorAll('#app ' + FOCUSABLE.split(', ').join(', #app '))].filter((el) => {
    if (!vis(el)) return false;
    const r = el.getBoundingClientRect();
    if (r.right > 0 && r.left < innerWidth) return false;
    // Reachable by scrolling only if its scroller is itself on screen.
    for (let n = el.parentElement; n && n !== document.body; n = n.parentElement) {
      const s = n.getBoundingClientRect();
      if (scrollsX(n) && s.right > 0 && s.left < innerWidth) return false;
    }
    return true;
  }).slice(0, 10).map(name);

  // 10. Column headers cut off ("STAT…", "METH…").
  out.clippedHeaders = all.filter((el) => el.matches('th, [role=columnheader]') && el.scrollWidth > el.clientWidth + 1).slice(0, 10).map(name);

  out.total = out.offscreenFocusable.length + out.clippedHeaders.length + out.strike.length + out.nestedPills.length + out.rowHeights.length + out.overflow.length + out.clippedControls.length + (out.pageScrollsSideways ? 1 : 0)
    + out.clippedText.length + Object.keys(out.containerStyles).length + out.uneven.length + out.lowContrastCount + out.smallTargets.length;
  return out;
})();
