/* OpenShield console.
 * No framework and no build step. Every string that comes from the API is
 * attacker-controlled, so it only ever reaches the DOM through textContent,
 * createTextNode or attribute/property setters. innerHTML is never used. */
'use strict';
(function () {
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const LABELS = ['ALLOWED_NORMAL', 'ALLOWED_UNUSUAL', 'SUSPICIOUS', 'MALICIOUS_CONFIRMED', 'POLICY_VIOLATION',
    'FALSE_POSITIVE', 'FALSE_NEGATIVE', 'UNKNOWN', 'NEEDS_REVIEW'];
  const ACTIONS = ['pass', 'allow', 'block', 'challenge'];
  const RANGES = ['5m', '15m', '1h', '6h', '24h', '7d'];
  const SEVERITIES = ['low', 'medium', 'high', 'critical'];
  const AI_CATEGORIES = ['legitimate', 'suspicious', 'malicious', 'policy_violation', 'unknown'];
  const TTLS = [[900, '15 minutes'], [3600, '1 hour'], [21600, '6 hours'], [86400, '24 hours'], [604800, '7 days'], [2592000, '30 days'], [0, 'No expiry']];
  const TITLES = { overview: 'Overview', live: 'Live', events: 'Events', alerts: 'Alerts', controls: 'Controls', policy: 'Policy', labels: 'Labels & datasets', ai: 'AI', audit: 'Audit', settings: 'Settings' };
  const SVGNS = 'http://www.w3.org/2000/svg';
  const $ = (id) => document.getElementById(id);
  const enc = encodeURIComponent;
  const S = { token: null, me: null, ctx: null, alertsOpen: 0 };
  let uidN = 0;
  const uid = (p) => (p || 'f') + '-' + (++uidN);

  // ------------------------------------------------------------------ storage (may throw in private modes)
  const store = {
    get(area, k) { try { return window[area].getItem(k); } catch (e) { return null; } },
    set(area, k, v) { try { window[area].setItem(k, v); } catch (e) { /* ignore */ } },
    del(area, k) { try { window[area].removeItem(k); } catch (e) { /* ignore */ } },
  };

  // ------------------------------------------------------------------ DOM helpers
  function h(tag, props) {
    const el = document.createElement(tag);
    if (props) setProps(el, props);
    for (let i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function setProps(el, props) {
    for (const k of Object.keys(props)) {
      const v = props[k];
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = String(v);
      else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k.slice(0, 5) === 'aria-' || k === 'role' || k === 'for') el.setAttribute(k, String(v));
      else if (k === 'style' || k === 'innerHTML' || k === 'outerHTML' || k === 'srcdoc') throw new Error('forbidden property ' + k);
      else el[k] = v;
    }
  }
  function add(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { for (const x of c) add(el, x); return; }
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  function icon(name) {
    const s = document.createElementNS(SVGNS, 'svg');
    s.setAttribute('class', 'ico');
    s.setAttribute('aria-hidden', 'true');
    const u = document.createElementNS(SVGNS, 'use');
    u.setAttribute('href', '#i-' + name);
    s.appendChild(u);
    return s;
  }
  function cvar(el, color) { el.style.setProperty('--c', color); return el; }

  // ------------------------------------------------------------------ formatting
  function compact(n) {
    if (n === null || n === undefined || n === '' || !isFinite(n)) return '–';
    n = Number(n);
    const a = Math.abs(n);
    if (a < 1000) {
      if (Number.isInteger(n)) return String(n);
      return (a < 10 ? n.toFixed(2) : n.toFixed(1)).replace(/\.?0+$/, '');
    }
    for (const [d, u] of [[1e12, 'T'], [1e9, 'B'], [1e6, 'M'], [1e3, 'k']]) {
      if (a >= d) { const v = n / d; return (Math.abs(v) < 10 ? v.toFixed(1) : v.toFixed(0)).replace(/\.0$/, '') + u; }
    }
    return String(n);
  }
  function full(n) { return isFinite(n) && n !== null ? Number(n).toLocaleString() : '–'; }
  function fmtMs(ms) {
    if (ms === null || ms === undefined || !isFinite(ms)) return '–';
    ms = Number(ms);
    if (ms < 0.01) return '<0.01 ms';
    if (ms < 10) return ms.toFixed(ms < 1 ? 2 : 1) + ' ms';
    if (ms < 1000) return Math.round(ms) + ' ms';
    return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + ' s';
  }
  function fmtBytes(b) {
    if (!isFinite(b) || b === null) return '–';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0; b = Number(b);
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(b < 10 ? 1 : 0) : b) + ' ' + u[i];
  }
  function pct(x, digits) { return isFinite(x) && x !== null ? (Number(x) * 100).toFixed(digits === undefined ? 0 : digits) + '%' : '–'; }
  function ratio(a, b) { return b > 0 && isFinite(a) ? a / b : null; }
  function score(x) { return isFinite(x) && x !== null ? Number(x).toFixed(2) : '–'; }
  function usd(x) { return isFinite(x) && x !== null ? '$' + (x < 1 ? Number(x).toFixed(4) : Number(x).toFixed(2)) : '–'; }
  function validTs(ts) { return ts !== null && ts !== undefined && isFinite(ts) && Number(ts) > 0; }
  function absTime(ts) {
    if (!validTs(ts)) return 'unknown time';
    return new Date(Number(ts)).toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  function clock(ts) {
    if (!validTs(ts)) return '—';
    const d = new Date(Number(ts));
    const p = (n, w) => String(n).padStart(w || 2, '0');
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) + '.' + p(d.getMilliseconds(), 3);
  }
  function relTime(ts, now) {
    if (!validTs(ts)) return '—';
    let s = Math.round(((now || Date.now()) - Number(ts)) / 1000);
    const fut = s < 0; s = Math.abs(s);
    if (s < 5) return fut ? 'in a moment' : 'just now';
    const t = s < 60 ? s + 's' : s < 3600 ? Math.floor(s / 60) + 'm' : s < 86400 ? Math.floor(s / 3600) + 'h' : Math.floor(s / 86400) + 'd';
    return fut ? 'in ' + t : t + ' ago';
  }
  function fmtDur(ms) {
    let s = Math.max(0, Math.floor(ms / 1000));
    const d = Math.floor(s / 86400); s -= d * 86400;
    const hh = Math.floor(s / 3600); s -= hh * 3600;
    const m = Math.floor(s / 60); s -= m * 60;
    if (d) return d + 'd ' + hh + 'h';
    if (hh) return hh + 'h ' + m + 'm';
    if (m) return m + 'm ' + s + 's';
    return s + 's';
  }
  function timeEl(ts, mode) {
    const el = h('time', { class: 'reltime nowrap', title: absTime(ts) });
    if (validTs(ts)) {
      el.dateTime = new Date(Number(ts)).toISOString();
      if (mode === 'clock') el.textContent = clock(ts);
      else { el.dataset.ts = String(Number(ts)); el.textContent = relTime(ts); }
    } else el.textContent = '—';
    return el;
  }
  setInterval(() => {
    for (const el of document.querySelectorAll('time.reltime[data-ts]')) el.textContent = relTime(Number(el.dataset.ts));
  }, 10000);
  function str(v) { return v === null || v === undefined ? '' : String(v); }
  function shortId(id) { const s = str(id); return s.length > 13 ? s.slice(0, 8) + '…' : s; }

  // ------------------------------------------------------------------ badges
  function actionBadge(a) {
    const k = ACTIONS.indexOf(a) >= 0 || a === 'suspicious' ? a : 'unknown';
    return h('span', { class: 'badge act-' + k, text: a == null || a === '' ? 'unknown' : String(a) });
  }
  function sevBadge(s) {
    const k = SEVERITIES.indexOf(s) >= 0 ? s : 'low';
    return h('span', { class: 'badge sev-' + k, text: s ? String(s) : 'unknown' });
  }
  const ST = new Set(['ok', 'applied', 'approved', 'resolved', 'active', 'degraded', 'ack', 'candidate', 'pending', 'queued', 'open', 'error', 'failed', 'rejected', 'denied', 'disabled', 'superseded']);
  function stBadge(s, text) {
    const k = ST.has(s) ? s : 'disabled';
    return h('span', { class: 'badge plain st-' + k, text: text || (s == null ? 'unknown' : String(s)) });
  }
  function labelBadge(l) {
    if (!l) return h('span', { class: 'faint', text: '—' });
    const c = /MALICIOUS|VIOLATION/.test(l) ? '--c-block' : l === 'SUSPICIOUS' ? '--c-suspicious' : /FALSE_/.test(l) ? '--c-challenge' : /^ALLOWED/.test(l) ? '--c-pass' : '--c-neutral';
    return cvar(h('span', { class: 'badge plain mono', text: String(l) }), 'var(' + c + ')');
  }
  function sourceBadge(src) {
    if (src === 'ai_candidate') return h('span', { class: 'badge ai-src', title: 'A model suggestion. Not ground truth until a person approves it.' }, icon('bot'), 'AI candidate');
    if (src === 'operator') return h('span', { class: 'badge op-src', title: 'Labelled by a person' }, icon('user'), 'Operator');
    if (src === 'rule') return h('span', { class: 'badge rule-src', title: 'Derived from a rule match' }, icon('policy'), 'Rule');
    return h('span', { class: 'badge rule-src', text: str(src) || 'unknown' });
  }
  function aiBadge(ai) {
    if (!ai || typeof ai !== 'object') return h('span', { class: 'faint', text: '—' });
    const cat = str(ai.category) || 'unknown';
    const k = cat === 'malicious' ? 'block' : (cat === 'suspicious' || cat === 'policy_violation') ? 'suspicious' : cat === 'legitimate' ? 'pass' : 'unknown';
    const label = cat.replace(/_/g, ' ');
    const risk = isFinite(ai.risk) && ai.risk !== null ? ' · risk ' + pct(ai.risk) : '';
    return h('span', { class: 'badge act-' + k, title: 'AI verdict (advisory, never enforced). Category ' + label + ', risk ' + score(ai.risk) + ', confidence ' + score(ai.confidence) }, label + risk);
  }
  function anomalyText(x) {
    if (!isFinite(x) || x === null) return h('span', { class: 'faint', text: '—' });
    const cls = x >= 0.8 ? 'an-hi' : x >= 0.5 ? 'an-mid' : 'an-lo';
    return h('span', { class: 'num ' + cls, text: score(x) + (x >= 0.8 ? ' high' : x >= 0.5 ? ' elev' : ''), title: 'Anomaly score ' + score(x) });
  }
  function meter(x, color) {
    const f = h('div', { class: 'bar-fill' });
    f.style.width = Math.max(0, Math.min(1, Number(x) || 0)) * 100 + '%';
    if (color) cvar(f, color);
    return h('div', { class: 'bar-track', 'aria-hidden': 'true' }, f);
  }
  function anomalyMeter(x) {
    const c = x >= 0.8 ? 'var(--c-block)' : x >= 0.5 ? 'var(--c-challenge)' : 'var(--c-pass)';
    return h('span', { class: 'meter' }, meter(x, c), anomalyText(x));
  }

  // ------------------------------------------------------------------ small UI pieces
  let alertToast = null, alertToastN = 0, alertToastTimer = 0;
  function alertToastShow(text) {
    const box = $('toasts');
    alertToastN++;
    if (!alertToast || !alertToast.isConnected) {
      alertToast = h('div', { class: 'toast toast-warn', role: 'status' });
      alertToastN = 1;
      box.appendChild(alertToast);
    }
    alertToast.replaceChildren(h('span', { text: alertToastN === 1 ? text : alertToastN + ' new high-severity alerts' }), ' ',
      h('a', { href: '#/alerts', text: 'View alerts' }));
    clearTimeout(alertToastTimer);
    alertToastTimer = setTimeout(() => { if (alertToast) alertToast.remove(); alertToast = null; alertToastN = 0; }, 6000);
  }
  function toast(msg, kind, ms) {
    const box = $('toasts');
    const t = h('div', { class: 'toast toast-' + (kind || 'info'), role: kind === 'error' ? 'alert' : 'status', text: msg });
    box.appendChild(t);
    while (box.children.length > 5) box.firstChild.remove();
    setTimeout(() => t.remove(), ms || (kind === 'error' ? 7000 : 4500));
  }
  function stateBox(kind, msg) {
    const kids = kind === 'loading' ? h('div', { class: 'spinner', 'aria-hidden': 'true' }) : kind === 'error' ? icon('close') : kind === 'locked' ? icon('lock') : null;
    return h('div', { class: 'state state-' + kind, role: kind === 'error' ? 'alert' : null, 'aria-busy': kind === 'loading' ? 'true' : null }, kids, h('p', { text: msg }));
  }
  function card(title, opts) {
    opts = opts || {};
    const head = h('div', { class: 'card-head' }, h('h2', { text: title }), opts.sub ? h('span', { class: 'faint', text: opts.sub }) : null, opts.actions || null);
    const body = h('div', { class: 'card-body' + (opts.flush ? ' flush' : '') });
    const el = h('section', { class: 'card ' + (opts.class || ''), 'aria-label': title }, head, body);
    return { el, head, body };
  }
  function pageHead(title) {
    const rest = Array.prototype.slice.call(arguments, 1);
    return h('div', { class: 'page-head' }, h('h1', { text: title }), rest);
  }
  function field(label, input, hintText) {
    if (!input.id) input.id = uid('fld');
    return h('div', { class: 'field' }, h('label', { for: input.id, text: label }), input, hintText ? h('p', { class: 'hint', text: hintText }) : null);
  }
  function select(options, value, props) {
    const s = h('select', props || null);
    for (const o of options) {
      const [v, t] = Array.isArray(o) ? o : [o, o];
      s.appendChild(h('option', { value: String(v), text: t, selected: String(v) === String(value) }));
    }
    return s;
  }
  function segmented(options, value, onChange, label) {
    const el = h('div', { class: 'seg', role: 'group', 'aria-label': label });
    const btns = [];
    for (const [v, t] of options) {
      const b = h('button', { type: 'button', text: t, 'aria-pressed': String(v === value) });
      b.addEventListener('click', () => {
        for (const x of btns) x.setAttribute('aria-pressed', String(x === b));
        onChange(v);
      });
      btns.push(b);
      el.appendChild(b);
    }
    return el;
  }
  function roleNote(role, what) { return h('p', { class: 'hint row' }, icon('lock'), what + ' requires the ' + role + ' role.'); }
  function filterLink(text, params, title) {
    return h('button', { type: 'button', class: 'btn-link mono ellipsis', text: text, title: title || 'Show events where this matches', onclick: () => go('events', params) });
  }
  function table(cols, rows, opts) {
    opts = opts || {};
    const thead = h('thead', null, h('tr', null, cols.map((c) => h('th', { class: c.num ? 'right' : '', scope: 'col', text: c.label }))));
    const tbody = h('tbody');
    for (const r of rows) tbody.appendChild(tableRow(cols, r, opts));
    const t = h('table', { class: 'tbl ' + (opts.class || '') }, opts.caption ? h('caption', { class: 'sr-only', text: opts.caption }) : null, thead, tbody);
    return h('div', { class: 'table-wrap' }, t);
  }
  function tableRow(cols, r, opts) {
    const tr = h('tr');
    if (opts.onRow) {
      tr.className = 'clickable';
      tr.tabIndex = 0;
      tr.addEventListener('click', (e) => { if (!e.target.closest('button,a,input,select,textarea')) opts.onRow(r, tr); });
      tr.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === tr) { e.preventDefault(); opts.onRow(r, tr); } });
    }
    for (const c of cols) {
      const v = c.render ? c.render(r) : r[c.key];
      tr.appendChild(h('td', { class: (c.num ? 'right num ' : '') + (c.cls || '') }, v instanceof Node ? v : (v === null || v === undefined || v === '' ? '—' : String(v))));
    }
    return tr;
  }
  function kv(pairs) {
    const dl = h('dl', { class: 'kv' });
    for (const [k, v] of pairs) {
      if (v === undefined) continue;
      dl.append(h('dt', { text: k }), h('dd', null, v instanceof Node ? v : (v === null || v === '' ? '—' : String(v))));
    }
    return dl;
  }
  function bars(entries, empty) {
    if (!entries.length) return stateBox('empty', empty || 'No data yet');
    const max = Math.max.apply(null, entries.map((e) => Number(e[1]) || 0).concat([1]));
    const total = entries.reduce((a, e) => a + (Number(e[1]) || 0), 0);
    return h('div', { class: 'bars' }, entries.map(([label, v, color]) => {
      const f = h('div', { class: 'bar-fill' });
      f.style.width = ((Number(v) || 0) / max) * 100 + '%';
      if (color) cvar(f, color);
      return h('div', { class: 'bar-row', title: str(label) + ': ' + full(v) + (total ? ' (' + pct(v / total, 1) + ')' : '') },
        label instanceof Node ? label : h('span', { class: 'ellipsis mono', text: str(label) }),
        h('div', { class: 'bar-track' }, f),
        h('span', { class: 'num muted', text: compact(v) }));
    }));
  }
  function objEntries(o) { return o && typeof o === 'object' ? Object.keys(o).map((k) => [k, o[k]]) : []; }
  function flatChips(obj) {
    const chips = [];
    for (const [k, v] of objEntries(obj)) {
      if (v && typeof v === 'object') { for (const [k2, v2] of objEntries(v)) chips.push([k + '.' + k2, v2]); } else chips.push([k, v]);
    }
    if (!chips.length) return h('span', { class: 'faint', text: '—' });
    return h('div', { class: 'chips' }, chips.slice(0, 40).map(([k, v]) => h('span', { class: 'chip' }, h('span', { class: 'mono', text: k + ': ' + (typeof v === 'number' ? full(v) : str(v)) }))));
  }
  function detailText(d) {
    if (d === null || d === undefined) return '—';
    if (typeof d !== 'object') return String(d);
    return objEntries(d).map(([k, v]) => k + ' ' + (v && typeof v === 'object' ? JSON.stringify(v) : str(v))).join(' · ');
  }
  function validIpOrCidr(v) {
    const m4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(v);
    if (m4) return m4.slice(1, 5).every((o) => +o <= 255) && (m4[5] === undefined || +m4[5] <= 32);
    const m6 = /^([0-9a-fA-F:.]+)(?:\/(\d{1,3}))?$/.exec(v);
    return !!m6 && m6[1].indexOf(':') >= 0 && m6[1].length <= 45 && (m6[2] === undefined || +m6[2] <= 128);
  }
  function looksLikeIp(v) { return typeof v === 'string' && validIpOrCidr(v) && v.indexOf('/') < 0; }

  // ------------------------------------------------------------------ API
  class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
  async function api(path, opts) {
    opts = opts || {};
    const headers = { Authorization: 'Bearer ' + S.token, Accept: 'application/json' };
    let body;
    if (opts.body !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.body); }
    let res;
    try {
      res = await fetch(path, { method: opts.method || 'GET', headers, body, cache: 'no-store', credentials: 'omit', redirect: 'error', signal: opts.signal });
    } catch (e) {
      if (e && e.name === 'AbortError') throw e;
      throw new ApiError(0, 'Cannot reach the admin server.');
    }
    if (res.status === 401) { logout('Your session is no longer valid. Sign in again.'); throw new ApiError(401, 'Unauthorized'); }
    if (res.status === 429) { const m = 'Rate limited by the admin server. Wait a minute and retry.'; toast(m, 'warn'); throw new ApiError(429, m); }
    if (!res.ok) {
      let msg = '';
      try { const j = await res.json(); if (j && typeof j.error === 'string') msg = j.error; } catch (e) { /* not JSON */ }
      if (!msg && res.status === 403) msg = 'Your role does not allow this action.';
      throw new ApiError(res.status, msg || 'Request failed (HTTP ' + res.status + ')');
    }
    if (opts.raw) return res;
    const txt = await res.text();
    if (!txt) return {};
    try { return JSON.parse(txt); } catch (e) { throw new ApiError(res.status, 'The server returned malformed JSON.'); }
  }
  function qs(params) {
    const u = new URLSearchParams();
    for (const k of Object.keys(params || {})) { const v = params[k]; if (v !== '' && v !== null && v !== undefined) u.set(k, String(v)); }
    const s = u.toString();
    return s ? '?' + s : '';
  }
  function can(role) { return !!S.me && (RANK[S.me.role] !== undefined ? RANK[S.me.role] : -1) >= RANK[role]; }
  // Runs an API action, toggling the button and reporting errors. Resolves to the result or null.
  async function act(btn, fn) {
    if (btn) btn.disabled = true;
    try { return await fn(); } catch (e) {
      if (e && e.status !== 401 && e.status !== 429 && e.name !== 'AbortError') toast(e.message || 'Action failed', 'error');
      return null;
    } finally { if (btn && btn.isConnected) btn.disabled = false; }
  }
  function changeResult(r, what) {
    if (r && r.status === 'pending') {
      toast(what + ' is pending approval by a second admin' + (r.change_id !== undefined ? ' (change #' + r.change_id + ')' : '') + '.', 'warn', 8000);
      return 'pending';
    }
    toast(what + ' applied.', 'ok');
    return 'applied';
  }

  // ------------------------------------------------------------------ modal dialog
  // `action` runs on confirm; returning a string keeps the dialog open and shows it as an error.
  function modal(o) {
    return new Promise((resolve) => {
      const dlg = $('modal'), form = $('modal-form'), okBtn = $('modal-ok'), cancelBtn = $('modal-cancel'), err = $('modal-error');
      if (dlg.open) dlg.close();
      $('modal-title').textContent = o.title;
      $('modal-body').replaceChildren();
      add($('modal-body'), o.body);
      err.textContent = '';
      okBtn.textContent = o.ok || 'OK';
      okBtn.className = 'btn btn-primary' + (o.danger ? ' btn-danger' : '');
      okBtn.hidden = !!o.hideOk;
      okBtn.disabled = false;
      cancelBtn.textContent = o.cancel || 'Cancel';
      dlg.classList.toggle('wide', !!o.wide);
      let busy = false;
      const done = (v) => {
        form.removeEventListener('submit', onSubmit);
        cancelBtn.removeEventListener('click', onCancel);
        dlg.removeEventListener('cancel', onEsc);
        if (dlg.open) dlg.close();
        resolve(v);
      };
      const onSubmit = async (e) => {
        e.preventDefault();
        if (busy) return;
        if (o.action) {
          busy = true; okBtn.disabled = true; err.textContent = '';
          let msg;
          try { msg = await o.action(); } catch (ex) { msg = ex && ex.message ? ex.message : 'Failed'; }
          busy = false; okBtn.disabled = false;
          if (msg) { err.textContent = msg; return; }
        }
        done(true);
      };
      const onCancel = () => done(false);
      const onEsc = (e) => { e.preventDefault(); if (!busy) done(false); };
      form.addEventListener('submit', onSubmit);
      cancelBtn.addEventListener('click', onCancel);
      dlg.addEventListener('cancel', onEsc);
      dlg.showModal();
      const first = $('modal-body').querySelector('input:not([type=hidden]),select,textarea');
      (first || (o.hideOk || o.danger ? cancelBtn : okBtn)).focus();
    });
  }
  function ttlSelect(def) { return select(TTLS.map(([v, t]) => [v, t]), def === undefined ? 3600 : def); }
  function ttlValue(sel) { const v = Number(sel.value); return v > 0 ? v : undefined; }

  async function blockDialog(value, reason, kind) {
    const allow = kind === 'allow';
    const val = h('input', { type: 'text', value: value || '', spellcheck: false, autocomplete: 'off', placeholder: '203.0.113.5 or 203.0.113.0/24' });
    const ttl = ttlSelect(3600);
    const rsn = h('input', { type: 'text', value: reason || '', maxLength: 300, placeholder: allow ? 'Why is this address trusted?' : 'Why is this address being blocked?' });
    let res = null;
    await modal({
      title: allow ? 'Allow IP address' : 'Block IP address', ok: allow ? 'Allow' : 'Block', danger: !allow,
      body: [field('IP or CIDR', val), field('Duration', ttl), field('Reason', rsn),
        h('p', { class: 'hint', text: allow ? 'An allowed address is exempt from dynamic blocks.' : 'Blocked clients get 403 before any rule runs (recorded as rule dynamic:ip_block). Long blocks may need approval by a second admin.' })],
      action: async () => {
        const v = val.value.trim();
        if (!validIpOrCidr(v)) return 'Enter a valid IPv4 or IPv6 address or CIDR.';
        if (!rsn.value.trim()) return 'A reason is required for the audit log.';
        try {
          const body = { value: v, reason: rsn.value.trim() };
          const t = ttlValue(ttl); if (t) body.ttl_s = t;
          const r = await api('/api/controls/' + (allow ? 'ip-allow' : 'ip-block'), { method: 'POST', body });
          changeResult(r, (allow ? 'Allow for ' : 'Block of ') + v);
          res = Object.assign({ value: v }, r);
        } catch (e) { return e.status === 401 ? undefined : e.message; }
      },
    });
    return res;
  }

  // ------------------------------------------------------------------ live stream (fetch + manual SSE parsing)
  const bus = { event: new Set(), stats: new Set(), alert: new Set(), ai: new Set() };
  const CAP = { event: 2000, stats: 900, alert: 200, ai: 2000 };
  let pend = { event: [], stats: [], alert: [], ai: [] };
  let flushScheduled = false;
  function enqueue(type, data) {
    const q = pend[type];
    if (!q) return;
    q.push(data);
    if (q.length > CAP[type]) q.splice(0, q.length - CAP[type]);
    if (!flushScheduled) {
      flushScheduled = true;
      // rAF batches to the frame rate; the timer keeps data moving when rAF is throttled or paused.
      flushRaf = document.hidden ? 0 : requestAnimationFrame(flush);
      flushTimer = setTimeout(flush, document.hidden ? 500 : 250);
    }
  }
  let flushRaf = 0, flushTimer = 0;
  // One DOM pass per frame no matter how many messages arrived.
  function flush() {
    if (!flushScheduled) return;
    flushScheduled = false;
    if (flushRaf) cancelAnimationFrame(flushRaf);
    clearTimeout(flushTimer);
    flushRaf = 0;
    const batch = pend;
    pend = { event: [], stats: [], alert: [], ai: [] };
    for (const type of Object.keys(batch)) {
      const q = batch[type];
      if (!q.length) continue;
      for (const fn of Array.from(bus[type])) { try { fn(q); } catch (e) { console.error(e); } }
    }
  }
  const conn = { ctrl: null, attempt: 0, timer: 0, cd: 0, watchdog: 0 };
  function setConn(state, text) { $('conn').dataset.state = state; $('conn-text').textContent = text; }
  function streamStop() {
    const c = conn.ctrl; conn.ctrl = null;
    if (c) c.abort();
    clearTimeout(conn.timer); clearInterval(conn.cd); clearTimeout(conn.watchdog);
    setConn('offline', 'Offline');
  }
  function streamStart() { streamStop(); conn.attempt = 0; connect(); }
  async function connect() {
    const ctrl = new AbortController();
    conn.ctrl = ctrl;
    setConn('connecting', 'Connecting…');
    const kick = () => { clearTimeout(conn.watchdog); conn.watchdog = setTimeout(() => ctrl.abort(), 45000); };
    try {
      kick();
      const res = await fetch('/api/stream', { headers: { Authorization: 'Bearer ' + S.token, Accept: 'text/event-stream' }, cache: 'no-store', credentials: 'omit', signal: ctrl.signal });
      if (res.status === 401) { logout('Your session is no longer valid. Sign in again.'); return; }
      if (res.status === 429) conn.attempt = Math.max(conn.attempt, 5);
      if (!res.ok || !res.body) throw new Error('HTTP ' + res.status);
      setConn('live', 'Live');
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '', evName = '', data = [], first = true;
      for (;;) {
        const r = await reader.read();
        if (r.done) break;
        kick();
        if (first) { first = false; conn.attempt = 0; }
        buf += dec.decode(r.value, { stream: true });
        const lines = buf.split(/\r\n|\r|\n/);
        buf = lines.pop();
        for (const line of lines) {
          if (line === '') {
            if (data.length) dispatchSse(evName || 'message', data.join('\n'));
            evName = ''; data = [];
            continue;
          }
          if (line.charCodeAt(0) === 58) continue; // ":" comment / keep-alive
          const i = line.indexOf(':');
          const fieldName = i < 0 ? line : line.slice(0, i);
          let val = i < 0 ? '' : line.slice(i + 1);
          if (val.charCodeAt(0) === 32) val = val.slice(1);
          if (fieldName === 'event') evName = val;
          else if (fieldName === 'data') data.push(val);
        }
        if (buf.length > 4194304) buf = ''; // refuse an unterminated multi-MB line
      }
    } catch (e) {
      if (conn.ctrl !== ctrl) return;
    } finally {
      if (conn.ctrl === ctrl) clearTimeout(conn.watchdog);
    }
    if (conn.ctrl !== ctrl || !S.token) return;
    scheduleReconnect();
  }
  function dispatchSse(name, raw) {
    if (!pend[name]) return;
    let d;
    try { d = JSON.parse(raw); } catch (e) { return; }
    if (d && typeof d === 'object') enqueue(name, d);
  }
  function scheduleReconnect() {
    const base = Math.min(30000, 1000 * Math.pow(2, conn.attempt));
    conn.attempt++;
    const delay = Math.round(base * (0.75 + Math.random() * 0.5));
    let left = Math.ceil(delay / 1000);
    setConn('reconnecting', 'Reconnecting in ' + left + 's');
    clearInterval(conn.cd);
    conn.cd = setInterval(() => { left--; if (left > 0) $('conn-text').textContent = 'Reconnecting in ' + left + 's'; }, 1000);
    conn.timer = setTimeout(() => { clearInterval(conn.cd); connect(); }, delay);
  }
  $('conn').addEventListener('click', () => { if (S.token && $('conn').dataset.state === 'reconnecting') streamStart(); });

  // global stream consumers
  bus.stats.add((ticks) => { const t = ticks[ticks.length - 1]; $('rps-val').textContent = compact(t.total); });
  // Alert messages also arrive when an existing alert is updated, so the
  // badge is re-read from the API (debounced) rather than incremented.
  let alertCountTimer = 0;
  const seenAlertIds = new Set();
  bus.alert.add((alerts) => {
    clearTimeout(alertCountTimer);
    alertCountTimer = setTimeout(refreshAlertCount, 1200);
    for (const a of alerts) {
      if (seenAlertIds.has(a.id)) continue;
      seenAlertIds.add(a.id);
      if ((a.status === 'open' || !a.status) && (a.severity === 'high' || a.severity === 'critical')) {
        alertToastShow('New ' + str(a.severity) + ' alert: ' + str(a.kind).replace(/_/g, ' ') + ' on ' + str(a.subject));
      }
    }
  });
  bus.ai.add((items) => {
    if (drawer.id && items.some((x) => str(x.event_id) === drawer.id)) { toast('AI verdict arrived for this event.', 'ok'); loadDrawer(); }
  });
  function renderAlertCount() {
    const el = $('alert-count');
    el.hidden = !(S.alertsOpen > 0);
    el.textContent = S.alertsOpen > 99 ? '99+' : String(S.alertsOpen);
    el.setAttribute('aria-label', S.alertsOpen + ' open alerts');
  }
  async function refreshAlertCount() {
    try { const r = await api('/api/alerts?status=open'); S.alertsOpen = Array.isArray(r.alerts) ? r.alerts.length : 0; renderAlertCount(); } catch (e) { /* non-fatal */ }
  }
  async function refreshDetectionMode() {
    try { const r = await api('/api/rules'); $('detect-banner').hidden = !r.detection_only; } catch (e) { /* non-fatal */ }
  }

  // ------------------------------------------------------------------ router
  const VIEWS = {};
  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, '');
    const q = raw.indexOf('?');
    const name = q < 0 ? raw : raw.slice(0, q);
    return { name: VIEWS[name] ? name : 'overview', params: new URLSearchParams(q < 0 ? '' : raw.slice(q + 1)) };
  }
  function go(name, params) {
    const target = '#/' + name + qs(params);
    if (location.hash === target) route(); else location.hash = target;
  }
  function makeCtx() {
    const ctx = {
      alive: true, cleanups: [],
      on(type, fn) { bus[type].add(fn); ctx.cleanups.push(() => bus[type].delete(fn)); },
      every(ms, fn) { const id = setInterval(fn, ms); ctx.cleanups.push(() => clearInterval(id)); },
      defer(fn) { ctx.cleanups.push(fn); },
    };
    return ctx;
  }
  function teardownView() {
    const c = S.ctx;
    if (!c) return;
    c.alive = false;
    for (const f of c.cleanups) { try { f(); } catch (e) { /* ignore */ } }
    S.ctx = null;
  }
  function route() {
    if (!S.me) return;
    teardownView();
    const { name, params } = parseHash();
    for (const a of document.querySelectorAll('#sidenav a')) {
      if (a.dataset.view === name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    }
    setNav(false);
    document.title = TITLES[name] + ' · OpenShield';
    const root = $('view');
    root.replaceChildren();
    root.scrollTop = 0;
    const ctx = makeCtx();
    S.ctx = ctx;
    try { VIEWS[name](root, params, ctx); } catch (e) {
      console.error(e);
      root.replaceChildren(stateBox('error', 'This view failed to render: ' + e.message));
    }
  }
  function setNav(open) {
    $('sidenav').classList.toggle('open', open);
    $('nav-scrim').hidden = !open;
    $('nav-toggle').setAttribute('aria-expanded', String(open));
    $('nav-toggle').setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  }

  // ------------------------------------------------------------------ traffic chart (canvas, stacked area)
  const SERIES = [['block', 'Block'], ['challenge', 'Challenge'], ['allow', 'Allow'], ['pass', 'Pass']];
  function niceStep(x) {
    if (!(x > 0)) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(x)));
    const f = x / p;
    const n = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return Math.max(1, n * p);
  }
  function axisLabel(t, rangeMs) {
    const d = new Date(t);
    const p = (n) => String(n).padStart(2, '0');
    if (rangeMs > 2 * 86400000) return d.toLocaleDateString(undefined, { weekday: 'short' }) + ' ' + p(d.getHours()) + ':00';
    if (rangeMs <= 900000) return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    return p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function trafficChart() {
    const wrap = h('div', { class: 'chart-wrap', tabIndex: 0, role: 'img', 'aria-label': 'Traffic over time. Use left and right arrow keys to inspect buckets.' });
    const canvas = h('canvas', { 'aria-hidden': 'true' });
    const tip = h('div', { class: 'chart-tip', hidden: true });
    const empty = h('div', { class: 'chart-empty', hidden: true, text: 'No traffic recorded in this range yet' });
    wrap.append(canvas, tip, empty);
    const hidden = new Set();
    const colors = {};
    let data = null, hover = -1, w = 0, hh = 0, dpr = 1, raf = 0;
    const pad = { l: 46, r: 12, t: 10, b: 24 };
    const legend = h('div', { class: 'legend', role: 'group', 'aria-label': 'Series' });
    for (const [k, label] of SERIES.slice().reverse()) {
      const b = h('button', { type: 'button', class: 'chip chip-toggle', 'aria-pressed': 'true', title: 'Show or hide ' + label }, cvar(h('span', { class: 'swatch' }), 'var(--c-' + k + ')'), label);
      cvar(b, 'var(--c-' + k + ')');
      b.addEventListener('click', () => {
        if (hidden.has(k)) hidden.delete(k); else hidden.add(k);
        b.setAttribute('aria-pressed', String(!hidden.has(k)));
        req();
      });
      legend.appendChild(b);
    }
    function readColors() {
      const cs = getComputedStyle(document.documentElement);
      for (const [k] of SERIES) colors[k] = cs.getPropertyValue('--c-' + k).trim() || '#888';
      colors.grid = cs.getPropertyValue('--chart-grid').trim();
      colors.axis = cs.getPropertyValue('--chart-axis').trim();
      colors.font = getComputedStyle(document.body).fontFamily;
    }
    function resize() {
      const r = wrap.getBoundingClientRect();
      dpr = window.devicePixelRatio || 1;
      w = Math.max(10, r.width); hh = Math.max(10, r.height);
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(hh * dpr);
      draw();
    }
    function req() { if (!raf) raf = requestAnimationFrame(() => { raf = 0; draw(); }); }
    function geom() {
      const s = (data && data.series) || [];
      const n = s.length, pw = w - pad.l - pad.r, ph = hh - pad.t - pad.b;
      const x = (i) => pad.l + (n <= 1 ? pw / 2 : (i * pw) / (n - 1));
      return { s, n, pw, ph, x };
    }
    function draw() {
      if (!w) return;
      const g = canvas.getContext('2d');
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      g.clearRect(0, 0, w, hh);
      const { s, n, pw, ph, x } = geom();
      empty.hidden = s.some((b) => (b.total || 0) > 0);
      if (!n) return;
      const vis = SERIES.map((a) => a[0]).filter((k) => !hidden.has(k));
      // Lines on a shared axis, not stacked: stacking hides small series
      // such as blocks under the pass volume.
      let max = 0;
      for (const b of s) for (const k of vis) { const v = Number(b[k]) || 0; if (v > max) max = v; }
      const step = niceStep(max / 4), yMax = step * 4;
      const y = (v) => pad.t + ph - (v / yMax) * ph;
      g.font = '11px ' + colors.font;
      g.lineWidth = 1;
      g.strokeStyle = colors.grid;
      g.fillStyle = colors.axis;
      g.textAlign = 'right'; g.textBaseline = 'middle';
      for (let i = 0; i <= 4; i++) {
        const yy = Math.round(y(step * i)) + 0.5;
        g.beginPath(); g.moveTo(pad.l, yy); g.lineTo(w - pad.r, yy); g.stroke();
        g.fillText(compact(step * i), pad.l - 6, yy);
      }
      const ticks = Math.max(2, Math.min(n, Math.floor(pw / 92)));
      g.textBaseline = 'top';
      for (let i = 0; i < ticks; i++) {
        const idx = Math.round((i * (n - 1)) / (ticks - 1));
        g.textAlign = i === 0 ? 'left' : i === ticks - 1 ? 'right' : 'center';
        g.fillText(axisLabel(s[idx].t, data.range_ms || 0), x(idx), hh - pad.b + 7);
      }
      // Pass first, so the smaller and more important series sit on top.
      for (const k of vis.slice().reverse()) {
        const val = (i) => Number(s[i][k]) || 0;
        g.beginPath();
        g.moveTo(x(0), y(val(0)));
        for (let i = 1; i < n; i++) g.lineTo(x(i), y(val(i)));
        g.lineTo(x(n - 1), y(0));
        g.lineTo(x(0), y(0));
        g.closePath();
        g.globalAlpha = k === 'pass' ? 0.06 : 0.12; g.fillStyle = colors[k]; g.fill(); g.globalAlpha = 1;
        g.beginPath();
        g.moveTo(x(0), y(val(0)));
        for (let i = 1; i < n; i++) g.lineTo(x(i), y(val(i)));
        g.strokeStyle = colors[k]; g.lineWidth = k === 'pass' ? 1.5 : 2; g.lineJoin = 'round'; g.lineCap = 'round'; g.stroke();
        if (n === 1) { g.beginPath(); g.arc(x(0), y(val(0)), 3, 0, Math.PI * 2); g.fillStyle = colors[k]; g.fill(); }
      }
      if (hover >= 0 && hover < n) {
        const xx = Math.round(x(hover)) + 0.5;
        g.strokeStyle = colors.axis; g.lineWidth = 1; g.setLineDash([3, 3]);
        g.beginPath(); g.moveTo(xx, pad.t); g.lineTo(xx, pad.t + ph); g.stroke();
        g.setLineDash([]);
      }
    }
    function showTip(idx) {
      const { s, n, x } = geom();
      if (!n) return;
      hover = Math.max(0, Math.min(n - 1, idx));
      const b = s[hover];
      tip.replaceChildren(h('div', { class: 'faint', text: absTime(b.t) }));
      for (const [k, label] of SERIES.slice().reverse()) {
        if (hidden.has(k)) continue;
        tip.appendChild(h('div', { class: 'tip-row' }, h('span', null, cvar(h('span', { class: 'swatch' }), 'var(--c-' + k + ')'), label), h('span', { text: full(b[k] || 0) })));
      }
      tip.appendChild(h('div', { class: 'tip-row' }, h('span', { text: 'Total' }), h('strong', { text: full(b.total || 0) })));
      if (b.suspicious) tip.appendChild(h('div', { class: 'tip-row' }, h('span', { text: 'Suspicious' }), h('span', { text: full(b.suspicious) })));
      if (b.p95_ms !== undefined && b.p95_ms !== null) tip.appendChild(h('div', { class: 'tip-row' }, h('span', { text: 'p95' }), h('span', { text: fmtMs(b.p95_ms) })));
      tip.hidden = false;
      const tw = tip.offsetWidth;
      let left = x(hover) + 12;
      if (left + tw > w - 4) left = x(hover) - tw - 12;
      tip.style.left = Math.max(4, left) + 'px';
      tip.style.top = pad.t + 'px';
      req();
    }
    function hideTip() { hover = -1; tip.hidden = true; req(); }
    wrap.addEventListener('mousemove', (e) => {
      const { n, pw } = geom();
      if (!n) return;
      const r = wrap.getBoundingClientRect();
      showTip(Math.round(((e.clientX - r.left - pad.l) / pw) * (n - 1)));
    });
    wrap.addEventListener('mouseleave', hideTip);
    wrap.addEventListener('blur', hideTip);
    wrap.addEventListener('keydown', (e) => {
      const { n } = geom();
      if (!n) return;
      const k = e.key;
      if (k === 'ArrowLeft' || k === 'ArrowRight' || k === 'Home' || k === 'End') {
        e.preventDefault();
        const cur = hover < 0 ? n - 1 : hover;
        showTip(k === 'Home' ? 0 : k === 'End' ? n - 1 : cur + (k === 'ArrowLeft' ? -1 : 1));
      } else if (k === 'Escape') hideTip();
    });
    const ro = new ResizeObserver(resize);
    ro.observe(wrap);
    const onTheme = () => { readColors(); draw(); };
    window.addEventListener('os-theme', onTheme);
    readColors();
    return {
      el: wrap, legend,
      set(d) {
        data = d;
        const s = d.series || [];
        const tot = s.reduce((a, b) => a + (b.total || 0), 0);
        wrap.setAttribute('aria-label', 'Traffic over ' + s.length + ' buckets: ' + full(tot) + ' requests. Arrow keys inspect buckets.');
        if (hover >= 0) showTip(hover); else req();
      },
      destroy() { ro.disconnect(); window.removeEventListener('os-theme', onTheme); if (raf) cancelAnimationFrame(raf); },
    };
  }

  // ------------------------------------------------------------------ view: overview
  VIEWS.overview = function (root, params, ctx) {
    let range = params.get('range') || store.get('localStorage', 'os-range') || '1h';
    if (RANGES.indexOf(range) < 0) range = '1h';
    const updated = h('span', { class: 'faint nowrap' });
    const refresh = h('button', { type: 'button', class: 'btn btn-icon', 'aria-label': 'Refresh overview', onclick: () => load() }, icon('refresh'));
    root.append(pageHead('Overview', segmented(RANGES.map((r) => [r, r]), range, (v) => { range = v; store.set('localStorage', 'os-range', v); data = null; load(true); }, 'Time range'), updated, refresh));

    // "Is anything wrong right now?" comes before any figure.
    const status = h('div', { class: 'status-strip', role: 'status', 'aria-live': 'polite' });
    root.appendChild(status);
    const KP = [
      ['requests', 'Requests', 'var(--c-neutral)'], ['block', 'Blocked', 'var(--c-block)'], ['challenge', 'Challenged', 'var(--c-challenge)'],
      ['suspicious', 'Suspicious', 'var(--c-suspicious)'], ['p95', 'Latency p95', 'var(--c-neutral)'], ['s5xx', '5xx errors', 'var(--c-high)'],
    ];
    const tiles = {};
    const kpis = h('div', { class: 'kpis' });
    for (const [k, label, c] of KP) {
      const val = h('div', { class: 'kpi-val', text: '–' });
      const sub = h('div', { class: 'kpi-sub', text: ' ' });
      const win = h('span', { class: 'kpi-win' });
      kpis.appendChild(cvar(h('div', { class: 'kpi', role: 'group', 'aria-label': label },
        h('div', { class: 'kpi-label' }, h('span', { class: 'kpi-dot', 'aria-hidden': 'true' }), h('span', { text: label }), win), val, sub), c));
      tiles[k] = { val, sub, win };
    }
    root.appendChild(kpis);

    const chart = trafficChart();
    ctx.defer(() => chart.destroy());
    const chartCard = card('Traffic', { actions: chart.legend });
    const bucketNote = h('span', { class: 'faint' });
    chartCard.head.insertBefore(bucketNote, chart.legend);
    chartCard.body.appendChild(chart.el);
    root.appendChild(chartCard.el);

    const ips = card('Top clients', { flush: true });
    const paths = card('Top paths', { flush: true });
    const rules = card('Rules matched', { flush: true });
    const codes = card('Status codes');
    const methods = card('Methods');
    const countries = card('Countries');
    const aiCard = card('AI analysis', { actions: h('a', { href: '#/ai', class: 'btn btn-sm', text: 'Details' }) });
    root.appendChild(h('div', { class: 'grid grid-4' }, ips.el, paths.el, rules.el));
    root.lastChild.style.marginTop = 'var(--gap)';
    ips.el.classList.add('span-2');
    root.appendChild(h('div', { class: 'grid grid-4' }, codes.el, methods.el, countries.el, aiCard.el));
    root.lastChild.style.marginTop = 'var(--gap)';
    for (const c of [ips, paths, rules, codes, methods, countries, aiCard]) c.body.replaceChildren(stateBox('loading', 'Loading…'));

    let data = null, loading = false;
    async function load(spinner) {
      if (loading) return;
      loading = true;
      if (spinner) chart.el.setAttribute('aria-busy', 'true');
      try {
        const d = await api('/api/overview' + qs({ range }));
        if (!ctx.alive) return;
        d.series = Array.isArray(d.series) ? d.series.filter((b) => b && isFinite(b.t)) : [];
        d.totals = d.totals || {};
        data = d;
        renderAll();
      } catch (e) {
        if (!ctx.alive || e.status === 401) return;
        if (!data) for (const c of [ips, paths, rules, codes, methods, countries, aiCard]) c.body.replaceChildren(stateBox('error', e.message));
        updated.textContent = 'Update failed: ' + e.message;
      } finally { loading = false; chart.el.removeAttribute('aria-busy'); }
    }
    function renderKpis() {
      const t = data.totals, lat = data.latency_ms || {};
      const req = t.requests;
      const share = (v) => req > 0 ? pct(ratio(v, req), v / req < 0.1 ? 1 : 0) + ' of requests' : 'no requests yet';
      const set = (k, v, sub, title) => { tiles[k].val.textContent = v; tiles[k].sub.textContent = sub || ' '; tiles[k].val.title = title || ''; tiles[k].win.textContent = 'last ' + range; };
      set('requests', compact(req), compact(data.rps_current) + ' req/s now · ' + fmtBytes(t.bytes_out) + ' sent', full(req) + ' requests');
      set('block', compact(t.block), share(t.block), full(t.block));
      set('challenge', compact(t.challenge), share(t.challenge), full(t.challenge));
      set('suspicious', compact(t.suspicious), 'anomaly ≥ 0.5 or AI-flagged', full(t.suspicious));
      set('p95', fmtMs(lat.p95), 'p50 ' + fmtMs(lat.p50) + ' · p99 ' + fmtMs(lat.p99));
      set('s5xx', compact(t.status_5xx), share(t.status_5xx), full(t.status_5xx));
    }
    function renderStatus() {
      const items = [];
      const al = data.alerts_open || {};
      const crit = al.critical || 0, high = al.high || 0, med = al.medium || 0, low = al.low || 0;
      let level = 'ok';
      const raise = (l) => { if (l === 'bad' || level === 'ok') level = l; };
      if (crit || high) {
        raise('bad');
        items.push(['bad', (crit ? crit + ' critical' + (high ? ' and ' : '') : '') + (high ? high + ' high' : '') + ' alert' + (crit + high === 1 ? '' : 's') + ' open', '#/alerts']);
      } else if (med || low) {
        raise('warn');
        items.push(['warn', (med + low) + ' lower-severity alert' + (med + low === 1 ? '' : 's') + ' open', '#/alerts']);
      }
      if (data.detection_only) { raise('warn'); items.push(['warn', 'Monitoring-only mode: rules log but do not block', '#/policy']); }
      const ai = data.ai || {};
      if (ai.state === 'open') { raise('warn'); items.push(['warn', 'AI analysis paused (provider failing); rules still enforce', '#/ai']); }
      else if (ai.state === 'degraded') items.push(['warn', 'AI analysis degraded', '#/ai']);
      const pl = data.pipeline || {};
      const lost = (pl.dropped || 0) + (pl.store_dropped || 0);
      if (lost > 0) { raise('warn'); items.push(['warn', compact(lost) + ' events not recorded (queue full)', null]); }
      status.dataset.level = level;
      const head = level === 'ok' ? 'All clear' : level === 'bad' ? 'Needs attention' : 'Check';
      const kids = [h('span', { class: 'status-icon', 'aria-hidden': 'true' }), h('strong', { text: head })];
      if (!items.length) kids.push(h('span', { class: 'muted', text: 'No open alerts. Rules enforcing' + (ai.state && ai.state !== 'disabled' ? ', AI analysis running.' : '.') }));
      for (const [lvl, text, href] of items) kids.push(href ? h('a', { class: 'status-item status-' + lvl, href, text }) : h('span', { class: 'status-item status-' + lvl, text }));
      kids.push(h('span', { class: 'status-meta faint', text: 'Policy v' + str(data.policy_version) }));
      status.replaceChildren.apply(status, kids);
    }
    function renderAll() {
      updated.textContent = 'Updated ' + clock(data.now || Date.now()).slice(0, 8);
      bucketNote.textContent = 'requests per ' + fmtDur(data.bucket_ms || 60000).replace(/ 0s$/, '') + ' bucket';
      renderStatus();
      renderKpis();
      if (data.alerts_open && isFinite(data.alerts_open.open)) { S.alertsOpen = data.alerts_open.open; renderAlertCount(); }
      chart.set(data);
      const tipIps = Array.isArray(data.top_ips) ? data.top_ips : [];
      ips.body.replaceChildren(tipIps.length ? table([
        { label: 'Client', render: (r) => filterLink(str(r.ip), { ip: r.ip }) },
        { label: 'Country', render: (r) => str(r.country) || '—' },
        { label: 'Requests', num: true, render: (r) => compact(r.count) },
        { label: 'Blocked', num: true, render: (r) => compact(r.blocked) },
        { label: 'Anomaly', render: (r) => anomalyMeter(r.anomaly_score) },
        { label: '', cls: 'actions', render: (r) => can('operator') ? h('button', { type: 'button', class: 'btn btn-sm btn-danger', text: 'Block', 'aria-label': 'Block ' + str(r.ip), onclick: () => blockDialog(str(r.ip), 'High anomaly score from overview') }) : '' },
      ], tipIps, { class: 'compact', caption: 'Top client IPs' }) : stateBox('empty', 'No clients in this range'));
      const tp = Array.isArray(data.top_paths) ? data.top_paths : [];
      paths.body.replaceChildren(tp.length ? table([
        { label: 'Path', cls: 'cell-path', render: (r) => filterLink(str(r.path), { path: r.path }) },
        { label: 'Req', num: true, render: (r) => compact(r.count) },
        { label: 'Blocked', num: true, render: (r) => compact(r.blocked) },
      ], tp, { class: 'compact' }) : stateBox('empty', 'No paths in this range'));
      const tr = Array.isArray(data.top_rules) ? data.top_rules : [];
      rules.body.replaceChildren(tr.length ? table([
        { label: 'Rule', cls: 'cell-path', render: (r) => filterLink(str(r.id), { rule: r.id }) },
        { label: 'Hits', num: true, render: (r) => compact(r.count) },
      ], tr, { class: 'compact' }) : stateBox('empty', 'No rule matched in this range'));
      const codeColor = { '2xx': 'var(--c-pass)', '3xx': 'var(--c-allow)', '4xx': 'var(--c-challenge)', '5xx': 'var(--c-block)' };
      codes.body.replaceChildren(bars(objEntries(data.status_codes).map(([k, v]) => [k, v, codeColor[k]]), 'No responses yet'));
      methods.body.replaceChildren(bars(objEntries(data.methods).sort((a, b) => b[1] - a[1]).slice(0, 8), 'No requests yet'));
      countries.body.replaceChildren(bars(objEntries(data.countries).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => [k || 'unknown', v, 'var(--c-allow)']), 'No geo data (GeoIP may be off)'));
      const ai = data.ai;
      if (!ai || ai.state === 'disabled') aiCard.body.replaceChildren(stateBox('empty', 'AI analysis is disabled.'));
      else aiCard.body.replaceChildren(kv([
        ['State', stBadge(ai.state)], ['Queue', compact(ai.queue)], ['Analyzed', compact(ai.analyzed)],
        ['Failures', compact(ai.failures)], ['Cache hits', compact(ai.cache_hits)], ['Cost', usd(ai.cost_usd)],
      ]), h('p', { class: 'hint', text: 'Verdicts are advisory and never enforce.' }));
    }
    const KEYS = ['total', 'pass', 'allow', 'block', 'challenge', 'suspicious'];
    function applyTick(t) {
      if (!isFinite(t.t)) return;
      const s = data.series, bm = data.bucket_ms || 60000, T = data.totals;
      if (t.t + 1000 <= (data.now || 0)) return; // already inside the snapshot
      let last = s[s.length - 1];
      if (last && t.t < last.t) return;
      if (!last || t.t >= last.t + bm) {
        const start = last ? last.t + Math.floor((t.t - last.t) / bm) * bm : Math.floor(t.t / bm) * bm;
        last = { t: start, total: 0, pass: 0, allow: 0, block: 0, challenge: 0, suspicious: 0, p95_ms: t.p95_ms };
        s.push(last);
      }
      for (const k of KEYS) { const v = Number(t[k]) || 0; last[k] = (last[k] || 0) + v; T[k === 'total' ? 'requests' : k] = (T[k === 'total' ? 'requests' : k] || 0) + v; }
      if (isFinite(t.p95_ms)) last.p95_ms = Math.max(Number(last.p95_ms) || 0, t.p95_ms);
      const minT = t.t - (data.range_ms || 3600000);
      while (s.length > 1 && s[0].t + bm <= minT) {
        const old = s.shift();
        for (const k of KEYS) { const tk = k === 'total' ? 'requests' : k; T[tk] = Math.max(0, (T[tk] || 0) - (Number(old[k]) || 0)); }
      }
      data.rps_current = Number(t.total) || 0;
      data.live_p95 = t.p95_ms;
      data.now = t.t + 1000;
    }
    ctx.on('stats', (ticks) => {
      if (!data) return;
      for (const t of ticks) applyTick(t);
      renderKpis();
      chart.set(data);
    });
    ctx.every(30000, () => load());
    load(true);
  };

  // ------------------------------------------------------------------ view: live tail
  VIEWS.live = function (root, params, ctx) {
    const MAX = 500, PER_FLUSH = 120;
    let paused = false, buffered = [], rate = 0, seen = 0, skipped = 0;
    const skipEl = h('span', { class: 'faint nowrap num', hidden: true, title: 'Rows skipped to keep the page responsive. Use Events to see every event.' });
    const shown = new Set(ACTIONS);
    let suspOnly = false;
    const rowsById = new Map();
    const evOf = new WeakMap();
    const pauseBtn = h('button', { type: 'button', class: 'btn', 'aria-pressed': 'false' }, icon('pause'), h('span', { text: 'Pause' }));
    const rateEl = h('span', { class: 'faint nowrap num', text: '0 ev/s' });
    const countEl = h('span', { class: 'faint nowrap num', text: '0 rows' });
    const clearBtn = h('button', { type: 'button', class: 'btn', text: 'Clear' });
    const chips = h('div', { class: 'chips', role: 'group', 'aria-label': 'Filter by action' });
    for (const a of ACTIONS) {
      const b = h('button', { type: 'button', class: 'chip chip-toggle', 'aria-pressed': 'true' }, actionBadge(a));
      cvar(b, 'var(--c-' + a + ')');
      b.addEventListener('click', () => { if (shown.has(a)) shown.delete(a); else shown.add(a); b.setAttribute('aria-pressed', String(shown.has(a))); refilter(); });
      chips.appendChild(b);
    }
    const susp = h('button', { type: 'button', class: 'chip chip-toggle', 'aria-pressed': 'false', text: 'Suspicious only' });
    cvar(susp, 'var(--c-suspicious)');
    susp.addEventListener('click', () => { suspOnly = !suspOnly; susp.setAttribute('aria-pressed', String(suspOnly)); refilter(); });
    chips.appendChild(susp);
    root.append(pageHead('Live', skipEl, rateEl, countEl, pauseBtn, clearBtn), h('div', { class: 'row', }, chips));
    root.lastChild.style.marginBottom = '10px';

    const tbody = h('tbody');
    const placeholder = h('tr', null, h('td', { colSpan: 9 }, stateBox('empty', 'Waiting for events from the live stream…')));
    tbody.appendChild(placeholder);
    const tbl = h('table', { class: 'tbl compact live-table' },
      h('thead', null, h('tr', null, ['Time', 'Action', 'Status', 'Method', 'Request', 'Client', 'Rules', 'Anomaly', 'AI'].map((t) => h('th', { scope: 'col', text: t })))), tbody);
    const c = card('Stream', { flush: true, sub: 'newest first · last ' + MAX + ' kept' });
    c.body.appendChild(h('div', { class: 'live-wrap table-wrap' }, tbl));
    root.appendChild(c.el);

    function match(ev) {
      if (!shown.has(ev.action) && ACTIONS.indexOf(ev.action) >= 0) return false;
      if (suspOnly && !((ev.anomaly_score || 0) >= 0.5 || (ev.ai && (ev.ai.category === 'suspicious' || ev.ai.category === 'malicious')))) return false;
      return true;
    }
    function row(ev) {
      const tr = h('tr', { class: 'clickable flash', tabIndex: 0 },
        h('td', null, timeEl(ev.ts, 'clock')),
        h('td', null, actionBadge(ev.action)),
        h('td', { class: 'num', text: str(ev.status) || '—' }),
        h('td', { class: 'mono', text: str(ev.method) }),
        h('td', { class: 'mono cell-path', title: str(ev.host) + str(ev.path) + (ev.query ? '?' + ev.query : '') }, str(ev.path), ev.query ? h('span', { class: 'faint', text: '?' + ev.query }) : null),
        h('td', { class: 'mono' }, str(ev.client_ip), ev.country ? h('span', { class: 'faint', text: ' ' + ev.country }) : null),
        h('td', { class: 'mono cell-path', text: Array.isArray(ev.rules) && ev.rules.length ? ev.rules.join(', ') : '—' }),
        h('td', null, anomalyText(ev.anomaly_score)),
        h('td', null, aiBadge(ev.ai)));
      evOf.set(tr, ev);
      return tr;
    }
    tbody.addEventListener('click', (e) => { const tr = e.target.closest('tr'); const ev = tr && evOf.get(tr); if (ev) openEvent(ev.id, tr); });
    tbody.addEventListener('keydown', (e) => { if (e.key !== 'Enter') return; const ev = evOf.get(e.target); if (ev) openEvent(ev.id, e.target); });
    function addRows(evs) {
      const list = evs.filter((e) => e && e.id !== undefined);
      if (!list.length) return;
      if (placeholder.isConnected) placeholder.remove();
      // Cap DOM work per flush; at very high rates the tail is sampled for display.
      const slice = list.slice(-PER_FLUSH);
      if (list.length > slice.length) { skipped += list.length - slice.length; skipEl.textContent = compact(skipped) + ' not shown (rate too high)'; skipEl.hidden = false; }
      const frag = document.createDocumentFragment();
      for (let i = slice.length - 1; i >= 0; i--) {
        const ev = slice[i];
        const tr = row(ev);
        tr.hidden = !match(ev);
        rowsById.set(str(ev.id), tr);
        frag.appendChild(tr);
      }
      tbody.insertBefore(frag, tbody.firstChild);
      while (tbody.rows.length > MAX) {
        const tr = tbody.lastElementChild;
        const ev = evOf.get(tr);
        if (ev) rowsById.delete(str(ev.id));
        tr.remove();
      }
      countEl.textContent = full(tbody.rows.length) + ' rows';
    }
    function refilter() { for (const tr of tbody.rows) { const ev = evOf.get(tr); if (ev) tr.hidden = !match(ev); } }
    function setPaused(p) {
      paused = p;
      pauseBtn.setAttribute('aria-pressed', String(p));
      pauseBtn.replaceChildren(icon(p ? 'play' : 'pause'), h('span', { text: p ? 'Resume' : 'Pause' }));
      if (!p && buffered.length) { addRows(buffered); buffered = []; }
    }
    pauseBtn.addEventListener('click', () => setPaused(!paused));
    clearBtn.addEventListener('click', () => { tbody.replaceChildren(placeholder); rowsById.clear(); buffered = []; countEl.textContent = '0 rows'; });
    ctx.on('event', (evs) => {
      rate += evs.length;
      if (paused) {
        buffered = buffered.concat(evs);
        if (buffered.length > MAX) buffered = buffered.slice(-MAX);
        seen += evs.length;
        pauseBtn.lastChild.textContent = 'Resume (' + compact(seen) + ' new)';
        return;
      }
      seen = 0;
      addRows(evs);
    });
    ctx.on('ai', (items) => {
      for (const it of items) {
        const tr = rowsById.get(str(it.event_id));
        if (!tr) continue;
        const ev = evOf.get(tr);
        if (ev) ev.ai = it.ai;
        tr.cells[8].replaceChildren(aiBadge(it.ai));
      }
    });
    ctx.every(1000, () => { rateEl.textContent = compact(rate) + ' ev/s'; rate = 0; if (!paused) seen = 0; });
  };

  // ------------------------------------------------------------------ view: events (virtualized)
  const FILTERS = ['action', 'ip', 'path', 'rule', 'q', 'min_anomaly', 'ai_category'];
  VIEWS.events = function (root, params, ctx) {
    const F = {};
    for (const k of FILTERS) F[k] = params.get(k) || '';
    const inputs = {
      action: select([['', 'Any action']].concat(ACTIONS.map((a) => [a, a])), F.action),
      ip: h('input', { type: 'text', value: F.ip, placeholder: '203.0.113.5', spellcheck: false, autocomplete: 'off' }),
      path: h('input', { type: 'text', value: F.path, placeholder: '/login', spellcheck: false, autocomplete: 'off' }),
      rule: h('input', { type: 'text', value: F.rule, placeholder: 'block-sqli-args', spellcheck: false, autocomplete: 'off' }),
      q: h('input', { type: 'search', value: F.q, placeholder: 'Search text', spellcheck: false, autocomplete: 'off' }),
      min_anomaly: h('input', { type: 'number', value: F.min_anomaly, min: 0, max: 1, step: 0.05, placeholder: '0.5' }),
      ai_category: select([['', 'Any AI verdict']].concat(AI_CATEGORIES.map((a) => [a, a])), F.ai_category),
    };
    const labels = { action: 'Action', ip: 'Client IP', path: 'Path', rule: 'Rule', q: 'Text', min_anomaly: 'Min anomaly', ai_category: 'AI category' };
    const form = h('form', { class: 'form-row', role: 'search', 'aria-label': 'Filter events' },
      FILTERS.map((k) => field(labels[k], inputs[k])),
      h('button', { type: 'submit', class: 'btn btn-primary' }, icon('filter'), 'Apply'),
      h('button', { type: 'button', class: 'btn', text: 'Reset', onclick: () => go('events') }));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const p = {};
      for (const k of FILTERS) p[k] = inputs[k].value.trim();
      go('events', p);
    });
    const active = FILTERS.filter((k) => F[k]);
    const activeChips = active.length ? h('div', { class: 'chips' }, h('span', { class: 'faint', text: 'Active:' }), active.map((k) => h('span', { class: 'chip' },
      h('span', { class: 'mono', text: labels[k] + ' = ' + F[k] }),
      h('button', { type: 'button', 'aria-label': 'Remove filter ' + labels[k], text: '×', onclick: () => { const p = Object.assign({}, F); p[k] = ''; go('events', p); } })))) : null;
    const reload = h('button', { type: 'button', class: 'btn btn-icon', 'aria-label': 'Reload events' }, icon('refresh'));
    root.append(pageHead('Events', reload));
    const fc = card('Filters');
    fc.body.append(form);
    if (activeChips) { activeChips.style.marginTop = '10px'; fc.body.append(activeChips); }
    root.append(fc.el);

    const ROW = 36, OVER = 8;
    const COLS = ['Time', 'Action', 'Status', 'Method', 'Request', 'Client', 'Rules', 'Anomaly', 'AI', 'Label'];
    const vbody = h('div', { class: 'vbody', role: 'rowgroup' });
    const vhead = h('div', { class: 'vhead', role: 'row' }, COLS.map((t) => h('div', { role: 'columnheader', text: t })));
    const inner = h('div', { class: 'vlist-inner', role: 'table', 'aria-label': 'Events', 'aria-rowcount': '-1' }, vhead, vbody);
    const vlist = h('div', { class: 'vlist' }, inner);
    const foot = h('div', { class: 'list-foot', role: 'status' });
    const lc = card('Results', { flush: true });
    lc.body.append(vlist, foot);
    lc.el.style.marginTop = 'var(--gap)';
    root.append(lc.el);

    let rows = [], next = null, loading = false, done = false, err = null, selected = null, rafId = 0;
    function cellsFor(ev) {
      const req = h('div', { class: 'mono', role: 'cell', title: str(ev.host) + str(ev.path) + (ev.query ? '?' + ev.query : '') }, str(ev.path), ev.query ? h('span', { class: 'faint', text: '?' + ev.query }) : null);
      return [
        h('div', { role: 'cell' }, timeEl(ev.ts, 'clock')),
        h('div', { role: 'cell' }, actionBadge(ev.action)),
        h('div', { role: 'cell', class: 'num', text: str(ev.status) || '—' }),
        h('div', { role: 'cell', class: 'mono', text: str(ev.method) }),
        req,
        h('div', { role: 'cell', class: 'mono' }, str(ev.client_ip), ev.country ? h('span', { class: 'faint', text: ' ' + ev.country }) : null),
        h('div', { role: 'cell', class: 'mono', text: Array.isArray(ev.rules) && ev.rules.length ? ev.rules.join(', ') : '—' }),
        h('div', { role: 'cell' }, anomalyText(ev.anomaly_score)),
        h('div', { role: 'cell' }, aiBadge(ev.ai)),
        h('div', { role: 'cell' }, labelBadge(ev.label)),
      ];
    }
    function render() {
      rafId = 0;
      vbody.style.height = rows.length * ROW + 'px';
      const top = Math.max(0, vlist.scrollTop - 32);
      const first = Math.max(0, Math.floor(top / ROW) - OVER);
      const last = Math.min(rows.length, Math.ceil((top + vlist.clientHeight) / ROW) + OVER);
      const focusedIdx = document.activeElement && document.activeElement.parentNode === vbody ? Number(document.activeElement.dataset.idx) : -1;
      const frag = document.createDocumentFragment();
      let refocus = null;
      for (let i = first; i < last; i++) {
        const ev = rows[i];
        const r = h('div', { class: 'vrow' + (selected === ev.id ? ' sel' : ''), role: 'row', tabIndex: 0, 'aria-rowindex': String(i + 2) }, cellsFor(ev));
        r.dataset.idx = String(i);
        r.style.top = i * ROW + 'px';
        if (i === focusedIdx) refocus = r;
        frag.appendChild(r);
      }
      vbody.replaceChildren(frag);
      if (refocus) refocus.focus({ preventScroll: true });
      if (!done && !loading && !err && last >= rows.length - 20) loadMore();
    }
    function schedule() { if (!rafId) rafId = requestAnimationFrame(render); }
    ctx.defer(() => { if (rafId) cancelAnimationFrame(rafId); });
    vlist.addEventListener('scroll', schedule, { passive: true });
    const ro = new ResizeObserver(schedule);
    ro.observe(vlist);
    ctx.defer(() => ro.disconnect());
    function openIdx(i, el) { const ev = rows[i]; if (!ev) return; selected = ev.id; openEvent(ev.id, el); schedule(); }
    vbody.addEventListener('click', (e) => { const r = e.target.closest('.vrow'); if (r) openIdx(Number(r.dataset.idx), r); });
    vbody.addEventListener('keydown', (e) => {
      const r = e.target.closest('.vrow');
      if (!r) return;
      const i = Number(r.dataset.idx);
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openIdx(i, r); return; }
      let j = -1;
      if (e.key === 'ArrowDown') j = Math.min(rows.length - 1, i + 1);
      else if (e.key === 'ArrowUp') j = Math.max(0, i - 1);
      else if (e.key === 'PageDown') j = Math.min(rows.length - 1, i + 10);
      else if (e.key === 'PageUp') j = Math.max(0, i - 10);
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = rows.length - 1;
      if (j < 0) return;
      e.preventDefault();
      const y = j * ROW + 32;
      if (y < vlist.scrollTop + 32) vlist.scrollTop = y - 32;
      else if (y + ROW > vlist.scrollTop + vlist.clientHeight) vlist.scrollTop = y + ROW - vlist.clientHeight;
      render();
      const t = vbody.querySelector('.vrow[data-idx="' + j + '"]');
      if (t) t.focus({ preventScroll: true });
    });
    function renderFoot() {
      const kids = [h('span', { text: rows.length ? full(rows.length) + ' events loaded' : '' })];
      if (loading) kids.push(h('span', { class: 'row' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), 'Loading…'));
      else if (err) kids.push(h('span', { class: 'state-error', text: err }), h('button', { type: 'button', class: 'btn btn-sm', text: 'Retry', onclick: () => { err = null; loadMore(); } }));
      else if (done) kids.push(h('span', { class: 'faint', text: rows.length ? 'End of results' : '' }));
      else kids.push(h('button', { type: 'button', class: 'btn btn-sm', text: 'Load more', onclick: loadMore }));
      foot.replaceChildren.apply(foot, kids);
      if (!rows.length && done && !err) vbody.replaceChildren(h('div', { class: 'state' }, h('p', { text: active.length ? 'No events match these filters.' : 'No events recorded yet.' })));
    }
    async function loadMore() {
      if (loading || done) return;
      loading = true; err = null; renderFoot();
      try {
        const p = Object.assign({}, F, { limit: 200 });
        if (next !== null) p.before = next;
        const r = await api('/api/events' + qs(p));
        if (!ctx.alive) return;
        const evs = Array.isArray(r.events) ? r.events.filter((e) => e && typeof e === 'object') : [];
        rows = rows.concat(evs);
        next = r.next_before === null || r.next_before === undefined ? null : r.next_before;
        if (next === null || !evs.length) done = true;
      } catch (e) {
        if (!ctx.alive) return;
        err = e.status === 401 ? null : e.message;
      } finally {
        loading = false;
      }
      renderFoot();
      if (rows.length) schedule();
    }
    reload.addEventListener('click', () => { rows = []; next = null; done = false; err = null; vlist.scrollTop = 0; vbody.replaceChildren(); loadMore(); });
    loadMore();
  };

  // ------------------------------------------------------------------ event drawer
  const drawer = { id: null, opener: null, seq: 0 };
  function openEvent(id, opener) {
    if (id === null || id === undefined || id === '') return;
    drawer.id = String(id);
    drawer.opener = opener || document.activeElement;
    $('drawer').hidden = false;
    $('drawer-scrim').hidden = false;
    document.body.classList.add('drawer-open');
    $('drawer-title').textContent = 'Event ' + shortId(id);
    loadDrawer();
    $('drawer-close').focus();
  }
  function closeDrawer() {
    if ($('drawer').hidden) return;
    $('drawer').hidden = true;
    $('drawer-scrim').hidden = true;
    document.body.classList.remove('drawer-open');
    drawer.id = null; drawer.seq++;
    $('drawer-body').replaceChildren();
    const o = drawer.opener;
    drawer.opener = null;
    if (o && o.isConnected && typeof o.focus === 'function') o.focus();
  }
  async function loadDrawer() {
    const my = ++drawer.seq;
    const body = $('drawer-body');
    if (!body.firstChild) body.replaceChildren(stateBox('loading', 'Loading event…'));
    let ev;
    try { ev = await api('/api/events/' + enc(drawer.id)); } catch (e) {
      if (my !== drawer.seq) return;
      body.replaceChildren(stateBox('error', e.status === 404 ? 'Event not found. It may have aged out of the store.' : e.message));
      return;
    }
    if (my !== drawer.seq || $('drawer').hidden) return;
    const st = body.scrollTop;
    body.replaceChildren.apply(body, eventDetail(ev));
    body.scrollTop = st;
  }
  function whyText(ev) {
    const mr = Array.isArray(ev.matched_rules) ? ev.matched_rules : [];
    const term = mr.filter((r) => r && ['block', 'challenge', 'allow'].indexOf(r.action) >= 0);
    const by = term.length ? term[term.length - 1].id : null;
    const note = ev.enforced === false ? ' Monitoring-only mode: this was not enforced.' : '';
    if (by === 'dynamic:ip_block') return 'Blocked by a dynamic IP block on ' + str(ev.client_ip) + ', before any rule ran.';
    if (ev.action === 'block') return 'Blocked by rule ' + str(by || '(unknown)') + '.' + note;
    if (ev.action === 'challenge') return 'Challenged by rule ' + str(by || '(unknown)') + ': the client must pass Turnstile.' + note;
    if (ev.action === 'allow') return 'Allowed by rule ' + str(by || '(unknown)') + '; later phases still ran.';
    if (mr.length) return 'Passed. Logged or scored by ' + mr.map((r) => str(r.id)).join(', ') + '.';
    return 'Passed: no rule matched.';
  }
  function section(title, extra) {
    const s = h('section', { class: 'section', 'aria-label': title }, h('h3', null, title, extra || null));
    return s;
  }
  function eventDetail(ev) {
    const out = [];
    const reqText = str(ev.method) + ' ' + str(ev.host) + str(ev.path) + (ev.query ? '?' + str(ev.query) : '') + (ev.protocol ? ' ' + str(ev.protocol) : '');
    let decoded = reqText;
    try { decoded = decodeURIComponent(reqText.replace(/\+/g, ' ')); } catch (e) { /* keep raw */ }
    out.push(h('div', { class: 'row' }, actionBadge(ev.action), h('span', { class: 'badge plain', text: 'HTTP ' + (str(ev.status) || '?') }),
      ev.label ? labelBadge(ev.label) : null, timeEl(ev.ts), h('span', { class: 'faint', text: fmtMs(ev.duration_ms) })));
    out.push(h('p', { class: 'why why-' + (ACTIONS.indexOf(ev.action) >= 0 ? ev.action : 'pass'), text: whyText(ev) }));
    const reqEl = h('div', { class: 'reqline', text: decoded });
    out.push(reqEl);
    if (decoded !== reqText) {
      const tg = h('button', { type: 'button', class: 'btn btn-sm', text: 'Show raw', 'aria-pressed': 'false' });
      tg.addEventListener('click', () => { const raw = tg.getAttribute('aria-pressed') !== 'true'; tg.setAttribute('aria-pressed', String(raw)); tg.textContent = raw ? 'Show decoded' : 'Show raw'; reqEl.textContent = raw ? reqText : decoded; });
      out.push(h('div', { class: 'row' }, h('span', { class: 'faint', text: 'Shown URL-decoded.' }), tg));
    }

    // decision
    const dec = section('Decision');
    const mr = Array.isArray(ev.matched_rules) ? ev.matched_rules : [];
    dec.appendChild(mr.length ? h('div', { class: 'chips' }, mr.map((r) => h('span', { class: 'chip' }, h('span', { class: 'mono', text: str(r && r.id) }), actionBadge(r && r.action))))
      : h('p', { class: 'muted', text: Array.isArray(ev.rules) && ev.rules.length ? 'Rules: ' + ev.rules.join(', ') : 'No rule matched. The request was passed by default.' }));
    const scores = objEntries(ev.scores);
    if (scores.length) dec.appendChild(h('div', { class: 'chips' }, h('span', { class: 'faint', text: 'Scores' }), scores.map(([k, v]) => h('span', { class: 'chip mono', text: k + ' ' + str(v) }))));
    const an = ev.anomaly || {};
    const reasons = Array.isArray(an.reasons) ? an.reasons : [];
    dec.appendChild(h('div', { class: 'row' }, h('span', { class: 'muted', text: 'Anomaly' }), anomalyMeter(an.score !== undefined ? an.score : ev.anomaly_score)));
    if (reasons.length) dec.appendChild(table([
      { label: 'Signal', cls: 'mono', render: (r) => str(r.kind) },
      { label: 'Detail', cls: 'wrap', render: (r) => str(r.detail) },
      { label: 'Weight', num: true, render: (r) => score(r.weight) },
    ], reasons, { class: 'compact' }));
    dec.childNodes.forEach((n, i) => { if (i) n.style.marginTop = '8px'; });
    out.push(dec);

    // AI
    const ai = section('AI verdicts', h('span', { class: 'badge ai-src', text: 'advisory' }));
    ai.appendChild(h('div', { class: 'callout callout-ai' }, icon('bot'), h('span', null, h('strong', { text: 'Advisory only. ' }), 'AI verdicts never block or allow traffic. Model output can be wrong or manipulated by the request itself; a person decides.')));
    const verdicts = Array.isArray(ev.ai_verdicts) ? ev.ai_verdicts : [];
    if (!verdicts.length) ai.appendChild(h('p', { class: 'muted', text: ev.ai ? 'Summary verdict only (no detail recorded).' : 'No AI verdict for this event.' }));
    if (!verdicts.length && ev.ai) ai.appendChild(aiBadge(ev.ai));
    for (const v of verdicts) {
      if (!v || typeof v !== 'object') continue;
      ai.appendChild(h('div', { class: 'verdict' },
        h('div', { class: 'row' }, aiBadge(v), v.status ? stBadge(v.status === 'ok' ? 'ok' : 'error', 'status ' + str(v.status)) : null, v.cached ? h('span', { class: 'badge plain', text: 'cached' }) : null, timeEl(v.ts)),
        kv([['Risk', score(v.risk)], ['Confidence', score(v.confidence)], ['Recommended', str(v.recommended_action) || '—'],
          ['Model', str(v.model) + (v.model_version ? ' · ' + str(v.model_version) : '')], ['Prompt', str(v.prompt_version) || '—'], ['Latency', fmtMs(v.latency_ms)]]),
        v.explanation ? h('p', { class: 'verdict-text', text: str(v.explanation) }) : null,
        Array.isArray(v.evidence) && v.evidence.length ? h('div', { class: 'chips' }, h('span', { class: 'faint', text: 'Evidence' }), v.evidence.map((x) => h('span', { class: 'chip mono', text: str(x) }))) : null));
    }
    out.push(ai);

    // labels
    const lb = section('Labels');
    const labels = Array.isArray(ev.labels) ? ev.labels : [];
    lb.appendChild(labels.length ? table([
      { label: 'Label', render: (r) => labelBadge(r.label) },
      { label: 'Source', render: (r) => sourceBadge(r.source) },
      { label: 'Status', render: (r) => stBadge(r.status) },
      { label: 'Reviewer', render: (r) => str(r.reviewer) || '—' },
      { label: 'Note', cls: 'wrap', render: (r) => str(r.note) || '—' },
      { label: 'When', render: (r) => timeEl(r.ts) },
    ], labels, { class: 'compact' }) : h('p', { class: 'muted', text: 'Not labelled yet.' }));
    out.push(lb);

    // client
    const cl = ev.client || {};
    const cs = section('Client');
    const clientIp = str(cl.ip || ev.client_ip);
    cs.appendChild(kv([
      ['IP', clientIp], ['Country', str(ev.country) || '—'], ['First seen', timeEl(cl.first_seen)], ['Requests', full(cl.requests)],
      ['Blocked', full(cl.blocked)], ['Anomaly', anomalyMeter(cl.anomaly_score)], ['Blocked now', cl.blocked_now ? stBadge('open', 'yes · dynamic block active') : 'no'],
    ]));
    const cb = h('div', { class: 'row' }, h('button', { type: 'button', class: 'btn btn-sm', onclick: () => { closeDrawer(); go('events', { ip: clientIp }); } }, icon('filter'), 'Events from this IP'));
    cb.style.marginTop = '8px';
    cs.appendChild(cb);
    out.push(cs);

    // request
    const rq = section('Request');
    rq.appendChild(kv([['ID', h('span', { class: 'mono', text: str(ev.id) })], ['Time', absTime(ev.ts)], ['Protocol', str(ev.protocol) || '—'],
      ['Bytes in / out', fmtBytes(ev.bytes_in) + ' / ' + fmtBytes(ev.bytes_out)], ['User agent', h('span', { class: 'mono', text: str(ev.user_agent) || '—' })]]));
    const hdrs = objEntries(ev.headers);
    const ht = h('div');
    ht.style.marginTop = '8px';
    ht.appendChild(hdrs.length ? table([
      { label: 'Header', cls: 'mono nowrap', render: (r) => r[0] },
      { label: 'Value (redacted)', cls: 'mono wrap', render: (r) => str(r[1]) },
    ], hdrs, { class: 'compact' }) : h('p', { class: 'muted', text: 'No headers recorded.' }));
    rq.appendChild(ht);
    const bh = h('h3', { text: 'Body excerpt' });
    bh.style.marginTop = '10px';
    rq.appendChild(bh);
    rq.appendChild(ev.body_excerpt !== null && ev.body_excerpt !== undefined && ev.body_excerpt !== '' ? h('pre', { class: 'codebox', text: str(ev.body_excerpt) }) : h('p', { class: 'muted', text: 'No body captured.' }));
    out.push(rq);

    // related
    const rel = Array.isArray(ev.related) ? ev.related : [];
    const rs = section('Related events');
    rs.appendChild(rel.length ? table([
      { label: 'Time', render: (r) => timeEl(r.ts) },
      { label: 'Action', render: (r) => actionBadge(r.action) },
      { label: 'Request', cls: 'mono cell-path', render: (r) => str(r.method) + ' ' + str(r.path) },
      { label: 'Status', num: true, render: (r) => str(r.status) },
    ], rel, { class: 'compact', onRow: (r) => openEvent(r.id, drawer.opener) }) : h('p', { class: 'muted', text: 'No related events.' }));
    out.push(rs);

    // actions
    const bar = h('div', { class: 'drawer-actions' });
    const formBox = h('div');
    if (can('analyst')) {
      bar.appendChild(h('button', { type: 'button', class: 'btn', onclick: () => { formBox.replaceChildren(labelForm(ev, formBox)); formBox.querySelector('select').focus(); } }, icon('labels'), 'Label'));
      const aiBtn = h('button', { type: 'button', class: 'btn' }, icon('ai'), 'Request AI analysis');
      aiBtn.addEventListener('click', () => act(aiBtn, async () => {
        const r = await api('/api/ai/analyze/' + enc(ev.id), { method: 'POST' });
        toast(r && r.status === 'queued' ? 'Queued for AI analysis. The verdict appears here when ready.' : 'AI analysis requested.', 'ok');
      }));
      bar.appendChild(aiBtn);
    }
    if (can('operator') && clientIp) {
      bar.appendChild(h('button', { type: 'button', class: 'btn btn-danger', onclick: async () => { if (await blockDialog(clientIp, 'From event ' + shortId(ev.id))) loadDrawer(); } }, icon('controls'), cl.blocked_now ? 'Extend block' : 'Block IP'));
    }
    if (!bar.childNodes.length) bar.appendChild(h('p', { class: 'hint row' }, icon('lock'), 'Viewer role: read-only.'));
    out.push(formBox, bar);
    return out;
  }
  function labelForm(ev, box) {
    const sel = select(LABELS, ev.label && LABELS.indexOf(ev.label) >= 0 ? ev.label : 'NEEDS_REVIEW');
    const note = h('textarea', { maxLength: 500, rows: 2, placeholder: 'Why? (optional)' });
    const save = h('button', { type: 'submit', class: 'btn btn-primary', text: 'Save label' });
    const f = h('form', { class: 'subform', 'aria-label': 'Label this event' }, field('Label', sel), field('Note', note),
      h('div', { class: 'row' }, save, h('button', { type: 'button', class: 'btn', text: 'Cancel', onclick: () => box.replaceChildren() })));
    f.addEventListener('submit', (e) => {
      e.preventDefault();
      act(save, async () => {
        await api('/api/events/' + enc(ev.id) + '/label', { method: 'POST', body: { label: sel.value, note: note.value.trim() } });
        toast('Label saved.', 'ok');
        box.replaceChildren();
        loadDrawer();
      });
    });
    return f;
  }
  $('drawer-close').addEventListener('click', closeDrawer);
  $('drawer-scrim').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => {
    if ($('modal').open) return;
    if (e.key === 'Escape') {
      if (!$('drawer').hidden) { e.preventDefault(); closeDrawer(); } else if ($('sidenav').classList.contains('open')) setNav(false);
      return;
    }
    if (e.key === 'Tab' && !$('drawer').hidden) {
      const f = Array.from($('drawer').querySelectorAll('button:not([disabled]),[href],input,select,textarea,[tabindex]:not([tabindex="-1"])')).filter((x) => !x.hidden && x.offsetParent !== null);
      if (!f.length) return;
      const firstEl = f[0], lastEl = f[f.length - 1];
      if (!$('drawer').contains(document.activeElement)) { e.preventDefault(); firstEl.focus(); } else if (e.shiftKey && document.activeElement === firstEl) { e.preventDefault(); lastEl.focus(); } else if (!e.shiftKey && document.activeElement === lastEl) { e.preventDefault(); firstEl.focus(); }
    }
  });

  // ------------------------------------------------------------------ view: alerts
  VIEWS.alerts = function (root, params, ctx) {
    const STATUSES = [['open', 'Open'], ['ack', 'Acknowledged'], ['resolved', 'Resolved'], ['all', 'All']];
    let status = params.get('status') || 'open';
    if (!STATUSES.some((s) => s[0] === status)) status = 'open';
    let sev = 'all';
    const list = h('div');
    root.append(pageHead('Alerts',
      segmented(STATUSES, status, (v) => { status = v; load(); }, 'Alert status'),
      segmented([['all', 'Any severity']].concat(SEVERITIES.map((s) => [s, s])), sev, (v) => { sev = v; render(); }, 'Severity')));
    const c = card('Alerts', { flush: true });
    c.body.appendChild(list);
    root.appendChild(c.el);
    if (!can('analyst')) { const n = roleNote('analyst', 'Acknowledging, resolving and AI summaries'); n.style.margin = '10px 0 0'; root.appendChild(n); }
    let alerts = null;
    async function load() {
      list.replaceChildren(stateBox('loading', 'Loading alerts…'));
      try {
        const r = await api('/api/alerts' + qs({ status: status === 'all' ? '' : status }));
        if (!ctx.alive) return;
        alerts = Array.isArray(r.alerts) ? r.alerts : [];
        if (status === 'open') { S.alertsOpen = alerts.length; renderAlertCount(); }
        render();
      } catch (e) { if (ctx.alive && e.status !== 401) list.replaceChildren(stateBox('error', e.message)); }
    }
    const KIND = { rate_spike: 'Rate spike', scanning: 'Scanning', attack_burst: 'Attack burst', error_burst: 'Error burst',
      traffic_spike: 'Traffic spike', ai_malicious: 'AI flagged allowed traffic', ai_degraded: 'AI analysis degraded' };
    function alertKind(k) { return KIND[k] || str(k).replace(/_/g, ' '); }
    function alertReason(a) {
      const d = a.detail && typeof a.detail === 'object' ? a.detail : {};
      if (d.reason) return str(d.reason);
      if (d.explanation) return 'AI (advisory): ' + str(d.explanation);
      if (d.note) return str(d.note);
      return detailText(d);
    }
    function subject(a) {
      const s = str(a.subject);
      if (looksLikeIp(s)) return filterLink(s, { ip: s });
      if (s.charAt(0) === '/') return filterLink(s, { path: s });
      return h('span', { class: 'mono', text: s || '—' });
    }
    function render() {
      if (!alerts) return;
      const rank = { critical: 3, high: 2, medium: 1, low: 0 };
      const rows = alerts.filter((a) => sev === 'all' || a.severity === sev)
        .sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0) || (b.last_ts || b.ts || 0) - (a.last_ts || a.ts || 0));
      if (!rows.length) { list.replaceChildren(stateBox('empty', status === 'open' ? 'No open alerts. All quiet.' : 'No alerts match.')); return; }
      const cols = [
        { label: 'Severity', render: (a) => sevBadge(a.severity) },
        { label: 'Alert', cls: 'wrap', render: (a) => h('div', { class: 'alert-what' },
          h('div', null, h('strong', { text: alertKind(a.kind) }), ' · ', subject(a)),
          h('div', { class: 'muted', text: alertReason(a) })) },
        { label: 'Seen', num: true, render: (a) => h('span', { title: 'Times this alert fired while open', text: compact(a.count) + '×' }) },
        { label: 'Last seen', render: (a) => timeEl(a.last_ts || a.ts) },
        { label: 'Status', render: (a) => stBadge(a.status, a.status === 'ack' ? 'acknowledged' : null) },
        { label: '', cls: 'actions', render: actions },
      ];
      const tbl = table(cols, [], { caption: 'Alerts' });
      const tbody = tbl.querySelector('tbody');
      for (const a of rows) {
        const tr = tableRow(cols, a, {});
        if (a._fresh) { tr.classList.add('flash'); a._fresh = false; }
        tbody.appendChild(tr);
        if (a.summary) {
          tbody.appendChild(h('tr', null, h('td', { colSpan: cols.length },
            h('div', { class: 'callout callout-ai' }, icon('bot'), h('div', null, h('strong', { text: 'AI summary (advisory) ' }), h('span', { class: 'verdict-text', text: str(a.summary) }))))));
        }
      }
      list.replaceChildren(tbl);
    }
    function actions(a) {
      if (!can('analyst')) return '';
      const wrap = h('span');
      const post = (verb, label, btnCls) => {
        const b = h('button', { type: 'button', class: 'btn btn-sm ' + (btnCls || ''), text: label, 'aria-label': label + ' alert ' + str(a.id) });
        b.addEventListener('click', () => act(b, async () => {
          const r = await api('/api/alerts/' + enc(a.id) + '/' + verb, { method: 'POST' });
          if (verb === 'summarize') { a.summary = r && typeof r.summary === 'string' ? r.summary : '(empty summary)'; render(); return; }
          toast('Alert ' + (verb === 'ack' ? 'acknowledged' : 'resolved') + '.', 'ok');
          refreshAlertCount();
          load();
        }));
        return b;
      };
      if (a.status === 'open') wrap.appendChild(post('ack', 'Ack'));
      if (a.status !== 'resolved') wrap.appendChild(post('resolve', 'Resolve'));
      wrap.appendChild(post('summarize', a.summary ? 'Re-summarize' : 'AI summary'));
      return wrap;
    }
    ctx.on('alert', (items) => {
      if (!alerts) return;
      for (const a of items) {
        if (status !== 'all' && a.status !== status) continue;
        const i = alerts.findIndex((x) => x.id === a.id);
        a._fresh = true;
        if (i >= 0) alerts[i] = a; else alerts.unshift(a);
      }
      render();
    });
    load();
  };

  // ------------------------------------------------------------------ view: controls
  VIEWS.controls = function (root, params, ctx) {
    const op = can('operator');
    root.append(pageHead('Controls'));
    root.appendChild(h('p', { class: 'hint', text: 'Dynamic IP blocks return 403 before any rule runs. Allowed addresses are exempt from dynamic blocks. Entries expire automatically when a duration is set.' }));
    root.lastChild.style.marginBottom = '12px';
    if (!op) { const n = roleNote('operator', 'Adding or removing blocks and allows'); n.style.marginBottom = '12px'; root.appendChild(n); }
    const pendingBox = h('div', { class: 'stack' });
    pendingBox.style.marginBottom = '12px';
    root.appendChild(pendingBox);
    const blocks = card('Dynamic IP blocks', { flush: true });
    const allows = card('IP allows', { flush: true });
    root.appendChild(h('div', { class: 'grid grid-2' }, blocks.el, allows.el));
    const countdowns = [];
    let reloadSoon = 0;
    if (op) { addButton(blocks, 'block'); addButton(allows, 'allow'); }

    function addButton(c, kind) {
      const allow = kind === 'allow';
      const b = h('button', { type: 'button', class: 'btn btn-sm ' + (allow ? 'btn-primary' : 'btn-primary btn-danger'), text: allow ? 'Add allow…' : 'Add block…' });
      b.addEventListener('click', async () => {
        const r = await blockDialog('', '', kind);
        if (!r || !ctx.alive) return;
        if (r.status === 'pending') {
          pendingBox.appendChild(h('div', { class: 'callout callout-warn', role: 'status' }, icon('lock'),
            h('span', null, h('strong', { text: 'Pending approval. ' }), (allow ? 'Allow for ' : 'Block of ') + r.value + ' awaits a second admin' + (r.change_id !== undefined ? ' (change #' + str(r.change_id) + ')' : '') + '. Admins approve it under Policy → Pending changes.')));
        }
        load();
      });
      c.head.appendChild(b);
    }
    function renderList(c, items, kind) {
      const path = kind === 'allow' ? 'ip-allow' : 'ip-block';
      const body = [];
      if (!items.length) body.push(stateBox('empty', kind === 'allow' ? 'No dynamic allows.' : 'No active dynamic blocks.'));
      else {
        body.push(table([
          { label: 'Value', render: (r) => looksLikeIp(r.value) ? filterLink(str(r.value), { ip: r.value }) : h('span', { class: 'mono', text: str(r.value) }) },
          { label: 'Expires', render: (r) => {
            if (!validTs(r.expires_at)) return h('span', { class: 'faint', text: 'never' });
            const el = h('span', { class: 'num nowrap', title: absTime(r.expires_at) });
            countdowns.push([el, Number(r.expires_at)]);
            return el;
          } },
          { label: 'Reason', cls: 'wrap', render: (r) => str(r.reason) || '—' },
          { label: 'By', render: (r) => str(r.actor) || '—' },
          { label: 'Added', render: (r) => timeEl(r.created_at) },
          { label: '', cls: 'actions', render: (r) => {
            if (!op) return '';
            const b = h('button', { type: 'button', class: 'btn btn-sm', text: 'Remove', 'aria-label': 'Remove ' + str(r.value) });
            b.addEventListener('click', async () => {
              const ok = await modal({ title: 'Remove ' + (kind === 'allow' ? 'allow' : 'block'), ok: 'Remove', danger: kind !== 'allow',
                body: h('p', null, 'Remove the dynamic ' + (kind === 'allow' ? 'allow' : 'block') + ' for ', h('code', { text: str(r.value) }), '?'),
                action: async () => { try { const res = await api('/api/controls/' + path + '/' + enc(str(r.value)), { method: 'DELETE' }); changeResult(res, 'Removal of ' + str(r.value)); } catch (e) { return e.status === 401 ? undefined : e.message; } } });
              if (ok) load();
            });
            return b;
          } },
        ], items, { class: 'compact' }));
      }
      c.body.replaceChildren.apply(c.body, body);
    }
    function tick() {
      const now = Date.now();
      for (const [el, exp] of countdowns) {
        if (!el.isConnected) continue;
        const left = exp - now;
        el.textContent = left > 0 ? 'in ' + fmtDur(left) : 'expired';
        if (left <= 0 && !reloadSoon) reloadSoon = setTimeout(() => { reloadSoon = 0; load(); }, 2000);
      }
    }
    async function load() {
      try {
        const r = await api('/api/controls');
        if (!ctx.alive) return;
        countdowns.length = 0;
        renderList(blocks, Array.isArray(r.ip_blocks) ? r.ip_blocks : [], 'block');
        renderList(allows, Array.isArray(r.ip_allows) ? r.ip_allows : [], 'allow');
        tick();
      } catch (e) {
        if (!ctx.alive || e.status === 401) return;
        blocks.body.replaceChildren(stateBox('error', e.message));
        allows.body.replaceChildren(stateBox('error', e.message));
      }
    }
    blocks.body.appendChild(stateBox('loading', 'Loading…'));
    allows.body.appendChild(stateBox('loading', 'Loading…'));
    ctx.every(1000, tick);
    ctx.every(30000, load);
    ctx.defer(() => clearTimeout(reloadSoon));
    load();
  };

  // ------------------------------------------------------------------ view: policy
  VIEWS.policy = function (root, params, ctx) {
    const admin = can('admin');
    const verPill = h('span', { class: 'badge plain', text: 'version …' });
    root.append(pageHead('Policy', verPill));
    const detect = h('div', { class: 'callout callout-warn', hidden: true }, icon('eye'), h('span', null, h('strong', { text: 'Monitoring-only mode is on. ' }), 'detection_only is true: rules are evaluated and logged but nothing is blocked or challenged.'));
    detect.style.marginBottom = '12px';
    root.appendChild(detect);

    const editor = h('textarea', { class: 'editor', spellcheck: false, autocomplete: 'off', readOnly: !admin, 'aria-label': 'Policy YAML', wrap: 'off' });
    editor.setAttribute('autocapitalize', 'off');
    const meta = h('p', { class: 'hint' });
    const dirty = h('span', { class: 'badge plain st-pending', text: 'unsaved edits', hidden: true });
    const bValidate = h('button', { type: 'button', class: 'btn', text: 'Validate' });
    const bSim = h('button', { type: 'button', class: 'btn', text: 'Simulate' });
    const bApply = h('button', { type: 'button', class: 'btn btn-primary', text: 'Apply…' });
    const bRevert = h('button', { type: 'button', class: 'btn', text: 'Revert edits' });
    const ed = card('Active policy', { actions: [dirty].concat(admin ? [bValidate, bSim, bApply, bRevert] : []) });
    ed.body.append(editor, meta,
      h('p', { class: 'hint', text: 'Only WAF keys belong here (rulesets, lists, scores, detection_only, …); server keys such as listen are rejected. Set detection_only: true for monitoring-only mode. Applying resets rate-limit counters.' }));
    if (!admin) ed.body.appendChild(roleNote('admin', 'Validating, simulating, applying and rolling back policy'));
    for (const n of ed.body.children) if (n !== editor) n.style.marginTop = '8px';
    const results = card('Result', { flush: false });
    results.el.hidden = true;
    const versions = card('Version history', { flush: true });
    const changes = card('Pending changes', { flush: true });
    const rulesCard = card('Rules', { flush: true });
    const left = h('div', { class: 'stack' }, ed.el, results.el);
    const right = h('div', { class: 'stack' }, versions.el, admin ? changes.el : null);
    root.appendChild(h('div', { class: 'grid grid-2' }, left, right));
    rulesCard.el.style.marginTop = 'var(--gap)';
    root.appendChild(rulesCard.el);
    for (const c of [versions, changes, rulesCard]) c.body.appendChild(stateBox('loading', 'Loading…'));
    editor.value = '';
    editor.placeholder = 'Loading policy…';

    let current = null;
    editor.addEventListener('input', () => { dirty.hidden = !current || editor.value === current.yaml; });
    bRevert.addEventListener('click', () => { if (current) { editor.value = current.yaml; dirty.hidden = true; } });

    function showResult(title, nodes) {
      results.head.firstChild.textContent = title;
      results.body.replaceChildren.apply(results.body, [].concat(nodes));
      results.el.hidden = false;
    }
    async function validate() {
      const r = await api('/api/policy/validate', { method: 'POST', body: { yaml: editor.value } });
      if (r.ok) showResult('Validation', h('div', { class: 'callout callout-ok', role: 'status' }, icon('check'), h('span', { text: 'Valid policy with ' + full(r.rule_count) + ' rules.' })));
      else showResult('Validation', h('div', { class: 'callout callout-danger', role: 'alert' }, icon('close'), h('pre', { text: str(r.error) || 'Invalid policy' })));
      return !!r.ok;
    }
    bValidate.addEventListener('click', () => act(bValidate, validate));
    bSim.addEventListener('click', () => act(bSim, async () => {
      showResult('Simulation', stateBox('loading', 'Replaying recent traffic against the candidate policy…'));
      let r;
      try { r = await api('/api/policy/simulate', { method: 'POST', body: { yaml: editor.value } }); } catch (e) { showResult('Simulation', h('div', { class: 'callout callout-danger', role: 'alert' }, h('pre', { text: e.message }))); return; }
      const cur = r.current || {}, cand = r.candidate || {};
      const keys = Array.from(new Set(Object.keys(cur).concat(Object.keys(cand))));
      const diffs = Array.isArray(r.diffs) ? r.diffs : [];
      showResult('Simulation (dry run)', [
        h('div', { class: 'stats' },
          h('div', { class: 'stat' }, h('div', { class: 'stat-label', text: 'Replayed' }), h('div', { class: 'stat-val', text: full(r.replayed) })),
          h('div', { class: 'stat' }, h('div', { class: 'stat-label', text: 'Changed' }), h('div', { class: 'stat-val', text: full(r.changed) + ' (' + pct(ratio(r.changed, r.replayed), 1) + ')' }))),
        h('h3', { text: 'Actions before → after' }),
        table([
          { label: 'Action', render: (k) => actionBadge(k) },
          { label: 'Current', num: true, render: (k) => full(cur[k] || 0) },
          { label: 'Candidate', num: true, render: (k) => full(cand[k] || 0) },
          { label: 'Δ', num: true, render: (k) => { const d = (cand[k] || 0) - (cur[k] || 0); return h('span', { class: d > 0 && (k === 'block' || k === 'challenge') ? 'delta-up' : d < 0 && (k === 'block' || k === 'challenge') ? 'delta-down' : '', text: (d > 0 ? '+' : '') + full(d) }); } },
        ], keys, { class: 'compact' }),
        h('h3', { text: 'Changed decisions' + (diffs.length > 200 ? ' (first 200 of ' + full(diffs.length) + ')' : '') }),
        diffs.length ? table([
          { label: 'Event', render: (d) => h('button', { type: 'button', class: 'btn-link mono', text: shortId(d.event_id), title: str(d.event_id), onclick: (e) => openEvent(d.event_id, e.currentTarget) }) },
          { label: 'Path', cls: 'mono cell-path', render: (d) => str(d.path) },
          { label: 'Current', render: (d) => actionBadge(d.current) },
          { label: 'Candidate', render: (d) => actionBadge(d.candidate) },
          { label: 'Rule', cls: 'mono', render: (d) => str(d.rule) || '—' },
        ], diffs.slice(0, 200), { class: 'compact' }) : h('p', { class: 'muted', text: 'No decision changed on the replayed sample.' }),
      ]);
      for (const n of results.body.children) n.style.marginTop = '8px';
    }));
    bApply.addEventListener('click', () => act(bApply, async () => {
      if (!(await validate())) { toast('Fix validation errors before applying.', 'error'); return; }
      const comment = h('textarea', { rows: 2, maxLength: 500, placeholder: 'What changes and why (required, audited)' });
      const ok = await modal({
        title: 'Apply policy: high-impact change', ok: 'Apply policy', danger: true,
        body: [h('div', { class: 'callout callout-danger' }, icon('policy'), h('span', null, h('strong', { text: 'This replaces the active WAF policy for all traffic immediately ' }), 'and resets rate-limit counters. Run Simulate first to preview the effect. With second-approver mode it becomes a pending change.')), field('Comment', comment)],
        action: async () => {
          if (!comment.value.trim()) return 'A comment is required.';
          try {
            const r = await api('/api/policy/apply', { method: 'POST', body: { yaml: editor.value, comment: comment.value.trim() } });
            changeResult(r, r && r.version !== undefined ? 'Policy version ' + r.version : 'Policy');
          } catch (e) { return e.status === 401 ? undefined : e.message; }
        },
      });
      if (ok) loadAll(true);
    }));

    async function viewVersion(v) {
      const pre = h('pre', { class: 'codebox', text: 'Loading…' });
      pre.style.maxHeight = '60vh';
      let yaml = null;
      const p = api('/api/policy/versions/' + enc(v)).then((r) => { yaml = str(r.yaml); pre.textContent = yaml; }).catch((e) => { pre.textContent = e.message; });
      const ok = await modal({ title: 'Policy version ' + v, wide: true, body: pre, ok: 'Load into editor', hideOk: !admin, cancel: 'Close' });
      await p;
      if (ok && yaml !== null) { editor.value = yaml; dirty.hidden = !current || yaml === current.yaml; editor.focus(); toast('Version ' + v + ' loaded into the editor. Validate and simulate before applying.', 'ok'); }
    }
    async function rollback(v) {
      const comment = h('textarea', { rows: 2, maxLength: 500, placeholder: 'Why roll back? (required, audited)' });
      const ok = await modal({
        title: 'Roll back to version ' + v + ': high-impact change', ok: 'Roll back', danger: true,
        body: [h('div', { class: 'callout callout-danger' }, icon('policy'), h('span', null, h('strong', { text: 'The active policy will be replaced by version ' + v + ' for all traffic ' }), 'and rate-limit counters reset. With second-approver mode it becomes a pending change.')), field('Comment', comment)],
        action: async () => {
          if (!comment.value.trim()) return 'A comment is required.';
          try { const r = await api('/api/policy/rollback', { method: 'POST', body: { version: v, comment: comment.value.trim() } }); changeResult(r, 'Rollback to version ' + v); } catch (e) { return e.status === 401 ? undefined : e.message; }
        },
      });
      if (ok) loadAll(true);
    }
    function renderVersions(list) {
      versions.body.replaceChildren(list.length ? table([
        { label: 'Ver', num: true, render: (r) => str(r.version) },
        { label: 'When', render: (r) => timeEl(r.ts) },
        { label: 'By', render: (r) => str(r.actor) || '—' },
        { label: 'Comment', cls: 'wrap', render: (r) => str(r.comment) || '—' },
        { label: 'Source', render: (r) => str(r.source) || '—' },
        { label: 'Status', render: (r) => stBadge(r.status) },
        { label: 'Rules', num: true, render: (r) => full(r.rule_count) },
        { label: '', cls: 'actions', render: (r) => {
          const w = h('span');
          w.appendChild(h('button', { type: 'button', class: 'btn btn-sm', text: 'View', 'aria-label': 'View version ' + str(r.version), onclick: () => viewVersion(r.version) }));
          if (admin && current && r.version !== current.version) w.appendChild(h('button', { type: 'button', class: 'btn btn-sm btn-danger', text: 'Roll back', 'aria-label': 'Roll back to version ' + str(r.version), onclick: () => rollback(r.version) }));
          return w;
        } },
      ], list, { class: 'compact' }) : stateBox('empty', 'No versions recorded.'));
    }
    function renderChanges(list) {
      changes.body.replaceChildren(list.length ? table([
        { label: '#', num: true, render: (c) => str(c.id) },
        { label: 'Kind', cls: 'mono', render: (c) => str(c.kind) },
        { label: 'Summary', cls: 'wrap', render: (c) => str(c.summary) },
        { label: 'Requested', render: (c) => h('span', null, str(c.requested_by), ' ', timeEl(c.ts)) },
        { label: '', cls: 'actions', render: (c) => {
          const mine = S.me && c.requested_by === S.me.name;
          const ap = h('button', { type: 'button', class: 'btn btn-sm btn-primary', text: 'Approve', disabled: mine, title: mine ? 'You requested this change; a different admin must approve it.' : '' });
          const rj = h('button', { type: 'button', class: 'btn btn-sm', text: 'Reject' });
          const go2 = (verb, b) => act(b, async () => { await api('/api/changes/' + enc(c.id) + '/' + verb, { method: 'POST' }); toast('Change #' + str(c.id) + ' ' + (verb === 'approve' ? 'approved' : 'rejected') + '.', 'ok'); loadAll(true); });
          ap.addEventListener('click', () => go2('approve', ap));
          rj.addEventListener('click', () => go2('reject', rj));
          return h('span', null, ap, rj);
        } },
      ], list, { class: 'compact' }) : stateBox('empty', 'No pending changes.'));
    }
    const ruleFilter = h('input', { type: 'search', placeholder: 'Filter rules', 'aria-label': 'Filter rules' });
    rulesCard.head.appendChild(ruleFilter);
    let rules = [];
    function renderRules() {
      const q = ruleFilter.value.trim().toLowerCase();
      const list = rules.filter((r) => !q || (str(r.id) + ' ' + str(r.description) + ' ' + str(r.ruleset) + ' ' + str(r.action)).toLowerCase().indexOf(q) >= 0);
      rulesCard.body.replaceChildren(list.length ? table([
        { label: 'Rule', render: (r) => filterLink(str(r.id), { rule: r.id }) },
        { label: 'Ruleset', cls: 'mono', render: (r) => str(r.ruleset) },
        { label: 'Phase', cls: 'mono', render: (r) => str(r.phase) },
        { label: 'Action', render: (r) => actionBadge(r.action) },
        { label: 'Enabled', render: (r) => r.enabled ? stBadge('ok', '✓ enabled') : stBadge('disabled', '✕ disabled') },
        { label: 'Description', cls: 'wrap', render: (r) => str(r.description) || '—' },
        { label: 'Hits 1h', num: true, render: (r) => compact(r.hits_1h) },
      ], list, { class: 'compact' }) : stateBox('empty', rules.length ? 'No rule matches the filter.' : 'No rules loaded.'));
    }
    ruleFilter.addEventListener('input', renderRules);

    async function loadAll(keepEditor) {
      const reqs = [api('/api/policy'), api('/api/policy/versions'), api('/api/rules')];
      if (admin) reqs.push(api('/api/changes?status=pending'));
      const [p, v, r, c] = await Promise.allSettled(reqs);
      if (!ctx.alive) return;
      if (p.status === 'fulfilled') {
        const wasDirty = current && editor.value !== current.yaml;
        current = p.value;
        if (!keepEditor || !wasDirty) editor.value = str(current.yaml);
        editor.placeholder = '';
        dirty.hidden = editor.value === str(current.yaml);
        verPill.textContent = 'version ' + str(current.version);
        meta.replaceChildren('Applied ', timeEl(current.applied_at), ' by ' + (str(current.actor) || 'unknown') + ' via ' + (str(current.source) || 'unknown') + '.');
      } else if (p.reason.status !== 401) { editor.placeholder = 'Could not load policy: ' + p.reason.message; }
      if (v.status === 'fulfilled') renderVersions(Array.isArray(v.value.versions) ? v.value.versions : []);
      else if (v.reason.status !== 401) versions.body.replaceChildren(stateBox('error', v.reason.message));
      if (r.status === 'fulfilled') {
        rules = Array.isArray(r.value.rules) ? r.value.rules.slice().sort((a, b) => (b.hits_1h || 0) - (a.hits_1h || 0)) : [];
        detect.hidden = !r.value.detection_only;
        $('detect-banner').hidden = !r.value.detection_only;
        renderRules();
      } else if (r.reason.status !== 401) rulesCard.body.replaceChildren(stateBox('error', r.reason.message));
      if (c) {
        if (c.status === 'fulfilled') renderChanges(Array.isArray(c.value.changes) ? c.value.changes : []);
        else if (c.reason.status !== 401) changes.body.replaceChildren(stateBox('error', c.reason.message));
      }
    }
    loadAll(false);
  };

  // ------------------------------------------------------------------ view: labels & datasets
  VIEWS.labels = function (root, params, ctx) {
    root.append(pageHead('Labels & datasets'));
    if (!can('analyst')) { root.appendChild(stateBox('locked', 'Label review and datasets require the analyst role.')); return; }
    root.appendChild(h('div', { class: 'callout callout-ai' }, icon('bot'), h('span', null, h('strong', { text: 'AI candidates are not ground truth. ' }), 'They are model suggestions and only count as training labels once a person approves them. A reviewer cannot approve their own label.')));
    root.lastChild.style.marginBottom = '12px';
    let status = 'candidate', source = 'all';
    const queueCard = card('Review queue', { flush: true, actions: [
      segmented([['candidate', 'Candidates'], ['approved', 'Approved'], ['rejected', 'Rejected']], status, (v) => { status = v; loadQueue(); }, 'Label status'),
      select([['all', 'All sources'], ['ai_candidate', 'AI candidates'], ['operator', 'Operators'], ['rule', 'Rules']], source, { 'aria-label': 'Label source', onchange: (e) => { source = e.target.value; renderQueue(); } }),
    ] });
    root.appendChild(queueCard.el);
    let labels = null;
    async function loadQueue() {
      queueCard.body.replaceChildren(stateBox('loading', 'Loading labels…'));
      try {
        const r = await api('/api/labels' + qs({ status }));
        if (!ctx.alive) return;
        labels = Array.isArray(r.labels) ? r.labels : [];
        renderQueue();
      } catch (e) { if (ctx.alive && e.status !== 401) queueCard.body.replaceChildren(stateBox('error', e.message)); }
    }
    function renderQueue() {
      if (!labels) return;
      const list = labels.filter((l) => source === 'all' || l.source === source);
      if (!list.length) { queueCard.body.replaceChildren(stateBox('empty', status === 'candidate' ? 'Nothing waiting for review.' : 'No labels with this status.')); return; }
      queueCard.body.replaceChildren(table([
        { label: 'Label', render: (l) => labelBadge(l.label) },
        { label: 'Source', render: (l) => sourceBadge(l.source) },
        { label: 'Event', cls: 'cell-path', render: (l) => {
          const e = l.event;
          if (!e) return h('button', { type: 'button', class: 'btn-link mono', text: shortId(l.event_id), onclick: (ev) => openEvent(l.event_id, ev.currentTarget) });
          return h('button', { type: 'button', class: 'btn-link mono ellipsis', title: str(e.method) + ' ' + str(e.path) + ' from ' + str(e.client_ip), onclick: (ev) => openEvent(l.event_id, ev.currentTarget) },
            str(e.action) + ' · ' + str(e.method) + ' ' + str(e.path) + ' · ' + str(e.client_ip));
        } },
        { label: 'Reviewer', render: (l) => str(l.reviewer) || '—' },
        { label: 'Note', cls: 'wrap', render: (l) => str(l.note) || '—' },
        { label: 'When', render: (l) => timeEl(l.ts) },
        { label: '', cls: 'actions', render: (l) => {
          if (l.status !== 'candidate') return stBadge(l.status);
          const mine = S.me && l.reviewer && l.reviewer === S.me.name;
          const ap = h('button', { type: 'button', class: 'btn btn-sm btn-primary', text: 'Approve', disabled: !!mine, title: mine ? 'You created this label; another reviewer must approve it.' : '' });
          const rj = h('button', { type: 'button', class: 'btn btn-sm', text: 'Reject' });
          const run = (verb, b) => act(b, async () => { await api('/api/labels/' + enc(l.id) + '/' + verb, { method: 'POST' }); toast('Label ' + (verb === 'approve' ? 'approved' : 'rejected') + '.', 'ok'); loadQueue(); });
          ap.addEventListener('click', () => run('approve', ap));
          rj.addEventListener('click', () => run('reject', rj));
          return h('span', null, ap, rj);
        } },
      ], list, { class: 'compact', caption: 'Label review queue' }));
    }

    const ds = card('Datasets', { flush: true });
    ds.el.style.marginTop = 'var(--gap)';
    root.appendChild(ds.el);
    const exportBox = h('div', { class: 'card-body' });
    const dsList = h('div');
    ds.body.append(exportBox, dsList);
    if (can('admin')) {
      const splitT = h('input', { type: 'radio', name: 'split', value: 'temporal', checked: true, id: uid('sp') });
      const splitE = h('input', { type: 'radio', name: 'split', value: 'entity', id: uid('sp') });
      const inc = h('input', { type: 'checkbox', id: uid('inc') });
      const warn = h('div', { class: 'callout callout-warn', hidden: true }, icon('bot'), h('span', null, h('strong', { text: 'Including AI candidates. ' }), 'Unreviewed model suggestions will be mixed into the training data. They are not ground truth and can teach a model its own mistakes.'));
      inc.addEventListener('change', () => { warn.hidden = !inc.checked; });
      const btn = h('button', { type: 'submit', class: 'btn btn-primary' }, icon('download'), 'Export dataset');
      const res = h('div');
      const f = h('form', { class: 'stack', 'aria-label': 'Export dataset' },
        h('fieldset', { class: 'plainset' }, h('legend', { class: 'muted', text: 'Split' }),
          h('label', { for: splitT.id, class: 'row' }, splitT, 'Temporal (train on older, test on newer)'),
          h('label', { for: splitE.id, class: 'row' }, splitE, 'Entity (no client appears in more than one split)')),
        h('label', { for: inc.id, class: 'row' }, inc, 'Include unreviewed AI candidates'), warn, h('div', null, btn), res);
      f.addEventListener('submit', (e) => {
        e.preventDefault();
        act(btn, async () => {
          const r = await api('/api/datasets/export', { method: 'POST', body: { split: splitE.checked ? 'entity' : 'temporal', include_candidates: inc.checked } });
          toast('Dataset version ' + str(r.version) + ' exported.', 'ok');
          res.replaceChildren(h('div', { class: 'callout callout-ok' }, icon('check'), h('div', null, h('strong', { text: 'Version ' + str(r.version) + ' ' }), flatChips(r.stats))));
          loadDatasets();
        });
      });
      exportBox.appendChild(f);
    } else exportBox.appendChild(roleNote('admin', 'Exporting and downloading datasets'));

    async function download(version, split, b) {
      await act(b, async () => {
        const res = await api('/api/datasets/' + enc(version) + '/' + enc(split), { raw: true });
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const name = ('openshield-dataset-v' + str(version) + '-' + split + '.jsonl').replace(/[^A-Za-z0-9._-]/g, '_');
        const a = h('a', { href: url, download: name, hidden: true });
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 30000);
      });
    }
    async function loadDatasets() {
      dsList.replaceChildren(stateBox('loading', 'Loading datasets…'));
      try {
        const r = await api('/api/datasets');
        if (!ctx.alive) return;
        const list = Array.isArray(r.datasets) ? r.datasets : [];
        dsList.replaceChildren(list.length ? table([
          { label: 'Ver', num: true, render: (d) => str(d.version) },
          { label: 'Created', render: (d) => timeEl(d.ts) },
          { label: 'By', render: (d) => str(d.actor) || '—' },
          { label: 'Stats', cls: 'wrap', render: (d) => flatChips(d.stats) },
          { label: 'Download', cls: 'actions', render: (d) => can('admin') ? h('span', { class: 'chips' }, ['train', 'validation', 'test', 'manifest'].map((s) => {
            const b = h('button', { type: 'button', class: 'btn btn-sm', 'aria-label': 'Download ' + s + ' split of version ' + str(d.version) }, icon('download'), s);
            b.addEventListener('click', () => download(d.version, s, b));
            return b;
          })) : '' },
        ], list, { class: 'compact' }) : stateBox('empty', 'No dataset exported yet.'));
      } catch (e) { if (ctx.alive && e.status !== 401) dsList.replaceChildren(stateBox('error', e.message)); }
    }
    loadQueue();
    loadDatasets();
  };

  // ------------------------------------------------------------------ view: AI
  VIEWS.ai = function (root, params, ctx) {
    const refresh = h('button', { type: 'button', class: 'btn btn-icon', 'aria-label': 'Refresh AI status', onclick: () => load() }, icon('refresh'));
    root.append(pageHead('AI analysis', refresh));
    root.appendChild(h('div', { class: 'callout callout-ai' }, icon('bot'), h('span', null, h('strong', { text: 'AI verdicts are advisory and never enforce. ' }),
      'The firewall decides with rules and dynamic controls only. A model reads redacted request summaries after the fact and suggests a category, a risk score and possible labels; people decide what to do with them. Requests themselves can try to manipulate the model, so treat explanations as untrusted text.')));
    root.lastChild.style.marginBottom = '12px';
    const body = h('div');
    root.appendChild(body);
    body.appendChild(stateBox('loading', 'Loading AI status…'));
    const STATE_TEXT = {
      ok: ['callout-ok', 'Healthy: verdicts are flowing.'],
      degraded: ['callout-warn', 'Degraded: the provider is slow or failing intermittently; some events are skipped.'],
      open: ['callout-danger', 'Circuit breaker open: calls to the provider are paused after repeated failures. They resume automatically.'],
      disabled: ['', 'AI analysis is disabled in configuration.'],
    };
    async function load() {
      try {
        const s = await api('/api/ai/status');
        if (!ctx.alive) return;
        const st = s.enabled === false ? 'disabled' : str(s.state) || 'disabled';
        const [cls, text] = STATE_TEXT[st] || ['', 'State: ' + st];
        const stat = (label, val, extra, title) => h('div', { class: 'stat', title: title || '' }, h('div', { class: 'stat-label', text: label }), h('div', { class: 'stat-val', text: val }), extra || null);
        const q = Number(s.queue) || 0, qc = Number(s.queue_capacity) || 0;
        const b = s.budget || {}, lat = s.latency_ms || {};
        const used = ratio(b.calls_today, b.max_calls_per_day);
        const nodes = [h('div', { class: 'callout ' + cls, role: 'status' }, h('span', { class: 'row' }, stBadge(st), h('span', { text: text })))];
        if (st !== 'disabled' || s.provider) {
          nodes.push(h('div', { class: 'stats' },
            stat('Provider', str(s.provider) || '—'), stat('Model', str(s.model) || '—'), stat('Breaker', st),
            stat('Queue', full(q) + (qc ? ' / ' + full(qc) : ''), qc ? meter(q / qc, q / qc > 0.8 ? 'var(--c-block)' : 'var(--c-allow)') : null),
            stat('Analyzed', compact(s.analyzed), null, full(s.analyzed)), stat('Failures', compact(s.failures)),
            stat('Invalid outputs', compact(s.invalid_outputs), null, 'Model responses that failed schema validation and were discarded'),
            stat('Cache hits', compact(s.cache_hits), h('div', { class: 'hint', text: 'hit rate ' + pct(ratio(s.cache_hits, (s.analyzed || 0) + (s.cache_hits || 0)), 0) })),
            stat('Dropped', compact(s.dropped), null, 'Events not analysed because the queue was full or the budget exhausted'),
            stat('Tokens in / out', compact(s.tokens_in) + ' / ' + compact(s.tokens_out)), stat('Cost', usd(s.cost_usd)),
            stat('Budget today', full(b.calls_today) + (b.max_calls_per_day ? ' / ' + full(b.max_calls_per_day) : ''), used !== null ? meter(used, used > 0.9 ? 'var(--c-block)' : used > 0.7 ? 'var(--c-challenge)' : 'var(--c-pass)') : null),
            stat('Latency p50 / p95', fmtMs(lat.p50) + ' / ' + fmtMs(lat.p95))));
          if (s.last_error) nodes.push(h('div', null, h('h3', { text: 'Last error' }), h('pre', { class: 'codebox', text: str(s.last_error) })));
        }
        body.replaceChildren(h('div', { class: 'stack' }, nodes));
      } catch (e) { if (ctx.alive && e.status !== 401) body.replaceChildren(stateBox('error', e.message)); }
    }
    ctx.every(10000, load);
    load();
  };

  // ------------------------------------------------------------------ view: audit
  VIEWS.audit = function (root, params, ctx) {
    if (!can('admin')) { root.append(pageHead('Audit'), stateBox('locked', 'The admin audit log is visible to admins only.')); return; }
    let limit = 200;
    const filter = h('input', { type: 'search', placeholder: 'Filter actor, action, target…', 'aria-label': 'Filter audit entries' });
    const lim = select([100, 200, 500, 1000], limit, { 'aria-label': 'Entries to load', onchange: (e) => { limit = Number(e.target.value); load(); } });
    const refresh = h('button', { type: 'button', class: 'btn btn-icon', 'aria-label': 'Refresh audit log', onclick: () => load() }, icon('refresh'));
    root.append(pageHead('Audit', filter, lim, refresh));
    const c = card('Admin audit log', { flush: true, sub: 'every state-changing API call' });
    root.appendChild(c.el);
    let entries = [];
    function render() {
      const q = filter.value.trim().toLowerCase();
      const list = entries.filter((e) => !q || [e.actor, e.role, e.action, e.target, e.result, e.ip, detailText(e.detail)].map(str).join(' ').toLowerCase().indexOf(q) >= 0);
      c.body.replaceChildren(list.length ? table([
        { label: 'When', render: (e) => timeEl(e.ts) },
        { label: 'Actor', render: (e) => str(e.actor) },
        { label: 'Role', render: (e) => h('span', { class: 'role', text: str(e.role) || '?' }) },
        { label: 'Action', cls: 'mono', render: (e) => str(e.action) },
        { label: 'Target', cls: 'mono wrap', render: (e) => str(e.target) || '—' },
        { label: 'Result', render: (e) => stBadge(/^(ok|applied|approved|success)$/.test(str(e.result)) ? 'ok' : e.result === 'pending' ? 'pending' : 'error', str(e.result) || '?') },
        { label: 'IP', cls: 'mono', render: (e) => str(e.ip) || '—' },
        { label: 'Detail', cls: 'mono wrap', render: (e) => detailText(e.detail) },
      ], list, { class: 'compact', caption: 'Audit log' }) : stateBox('empty', entries.length ? 'No entry matches the filter.' : 'No audit entries yet.'));
    }
    filter.addEventListener('input', render);
    async function load() {
      c.body.replaceChildren(stateBox('loading', 'Loading audit log…'));
      try {
        const r = await api('/api/audit' + qs({ limit }));
        if (!ctx.alive) return;
        entries = Array.isArray(r.entries) ? r.entries : [];
        render();
      } catch (e) { if (ctx.alive && e.status !== 401) c.body.replaceChildren(stateBox('error', e.message)); }
    }
    load();
  };

  // ------------------------------------------------------------------ view: settings (admin)
  // Secrets are write-only: the API only says whether one is set. Leaving a
  // secret field empty keeps the stored value.
  function checkbox(label, checked, hint) {
    const box = h('input', { type: 'checkbox', checked: !!checked, id: uid('cb') });
    const el = h('div', { class: 'field field-check' }, h('label', { for: box.id, class: 'check' }, box, h('span', { text: label })), hint ? h('p', { class: 'hint', text: hint }) : null);
    return { el, box };
  }
  function numInput(value, min, max, step) {
    return h('input', { type: 'number', value: value === null || value === undefined ? '' : String(value), min: String(min), max: String(max), step: String(step || 1), inputmode: 'decimal' });
  }
  function secretInput(isSet, what) {
    return h('input', { type: 'password', autocomplete: 'new-password', spellcheck: false,
      placeholder: isSet ? what + ' is set. Leave empty to keep it.' : 'Not set' });
  }
  function sourceBadge2(src, updated) {
    const txt = src === 'dashboard' ? 'Saved in dashboard' : 'From config file';
    const b = h('span', { class: 'badge plain', text: txt });
    if (updated && updated.updated_ts) b.title = 'Changed by ' + str(updated.updated_by) + ', ' + absTime(updated.updated_ts);
    return b;
  }
  async function copyText(text, fallbackInput) {
    try { await navigator.clipboard.writeText(text); toast('Copied.', 'ok'); } catch (e) {
      if (fallbackInput) { fallbackInput.focus(); fallbackInput.select(); }
      toast('Copy is blocked here; the token is selected, press Ctrl/Cmd+C.', 'warn', 7000);
    }
  }
  // Shows a token once. Resolves when the person confirms they stored it.
  function showTokenOnce(name, token, note) {
    const out = h('input', { type: 'text', value: token, readOnly: true, class: 'mono', spellcheck: false });
    const copy = h('button', { type: 'button', class: 'btn', text: 'Copy' });
    copy.addEventListener('click', () => copyText(token, out));
    return modal({
      title: 'Token for ' + name, ok: 'I stored it', hideOk: false, cancel: 'Close',
      body: [h('div', { class: 'callout callout-warn' }, icon('lock'), h('span', { text: note || 'Copy this token now. Only its hash is stored, so it cannot be shown again.' })),
        field('Token', h('div', { class: 'row token-row' }, out, copy))],
    });
  }

  VIEWS.settings = function (root, params, ctx) {
    const TABS = [['ai', 'AI'], ['challenge', 'Challenge'], ['users', 'Users & tokens'], ['storage', 'Event storage'], ['security', 'Security']];
    let tab = params.get('tab') || (S.me && S.me.setup_mode ? 'users' : 'ai');
    if (!TABS.some((t) => t[0] === tab)) tab = 'ai';
    const body = h('div', { class: 'settings-body' });
    root.append(pageHead('Settings', segmented(TABS, tab, (v) => { tab = v; render(); }, 'Settings section')));
    if (S.me && S.me.setup_mode) {
      root.appendChild(h('div', { class: 'callout callout-warn setup-banner' }, icon('lock'),
        h('span', null, h('strong', { text: 'First-run setup. ' }), 'Create an admin user under Users & tokens, then sign in with its token. The setup token stops working as soon as the first admin exists.')));
    }
    root.appendChild(body);
    let data = null;
    async function load() {
      body.replaceChildren(stateBox('loading', 'Loading settings…'));
      try { data = await api('/api/settings'); if (ctx.alive) render(); } catch (e) {
        if (ctx.alive && e.status !== 401) body.replaceChildren(stateBox('error', e.message));
      }
    }
    function render() {
      if (!data) return;
      const fn = { ai: aiCard, challenge: challengeCard, users: usersCard, storage: storageCard, security: securityCard }[tab];
      body.replaceChildren(fn());
    }

    function aiCard() {
      const a = data.ai, v = a.values, key = a.api_key;
      const c = card('AI analysis (Gemini)', { actions: sourceBadge2(a.source, a.updated) });
      const status = a.running
        ? h('div', { class: 'callout callout-ok' }, icon('ai'), h('span', { text: 'Running: model ' + str(v.model) + '. Key from ' + str(key.source) + '.' }))
        : h('div', { class: 'callout' + (v.enabled ? ' callout-warn' : '') }, icon('ai'), h('span', { text: 'Off: ' + str(a.off_reason || 'disabled') + '.' }));
      const enabled = checkbox('Enable AI analysis', v.enabled, 'Verdicts are advisory: they never block or allow traffic.');
      const keyIn = secretInput(key.set, 'An API key');
      const clearKey = checkbox('Remove the saved API key', false);
      const model = h('input', { type: 'text', value: str(v.model), spellcheck: false, autocomplete: 'off', placeholder: 'Model id from Google AI Studio' });
      const baseUrl = h('input', { type: 'url', value: str(v.base_url), spellcheck: false });
      const rpm = numInput(v.requests_per_minute, 1, 10000);
      const perDay = numInput(v.max_calls_per_day, 0, 10000000);
      const timeout = numInput(v.timeout_ms, 500, 60000, 100);
      const sendBody = checkbox('Send redacted request bodies to the model', v.send_body, 'Off by default. Bodies can hold personal data even after redaction.');
      const priceIn = numInput(v.price_per_mtok_in, 0, 1000, 0.01);
      const priceOut = numInput(v.price_per_mtok_out, 0, 1000, 0.01);
      const trig = h('div', { class: 'chips', role: 'group', 'aria-label': 'Analyze these events' });
      const trigBoxes = {};
      for (const t of a.triggers_available || []) {
        const b = checkbox(t.replace('_', ' '), (v.triggers || []).indexOf(t) >= 0);
        trigBoxes[t] = b.box;
        trig.appendChild(b.el);
      }
      const save = h('button', { type: 'submit', class: 'btn btn-primary', text: 'Save' });
      const test = h('button', { type: 'button', class: 'btn', text: 'Test connection' });
      const reset = h('button', { type: 'button', class: 'btn', text: 'Reset to config file' });
      const result = h('p', { class: 'hint', role: 'status' });
      const form = h('form', { class: 'settings-form' },
        status,
        enabled.el,
        h('div', { class: 'grid grid-2' },
          field('API key', keyIn, key.set ? 'Stored encrypted. Get a key at aistudio.google.com.' : 'Get a key at aistudio.google.com. Stored encrypted; never shown again. Or set ' + str(key.env_var) + ' on the server.'),
          field('Model', model, 'For example a Flash model; check AI Studio for current ids.')),
        key.set && key.source && key.source.indexOf('dashboard') >= 0 ? clearKey.el : null,
        h('div', { class: 'grid grid-3' }, field('Requests per minute', rpm), field('Calls per day (budget)', perDay), field('Timeout (ms)', timeout)),
        field('Analyze these events', trig),
        sendBody.el,
        h('details', { class: 'advanced' }, h('summary', { text: 'Advanced' }),
          h('div', { class: 'grid grid-3' }, field('API base URL', baseUrl), field('USD per 1M input tokens', priceIn, 'For the cost estimate only.'), field('USD per 1M output tokens', priceOut))),
        h('div', { class: 'row form-actions' }, save, test, a.source === 'dashboard' ? reset : null, result));
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        act(save, async () => {
          const triggers = Object.keys(trigBoxes).filter((t) => trigBoxes[t].checked);
          const payload = { enabled: enabled.box.checked, model: model.value.trim(), base_url: baseUrl.value.trim(),
            timeout_ms: Number(timeout.value), requests_per_minute: Number(rpm.value), max_calls_per_day: Number(perDay.value),
            triggers, send_body: sendBody.box.checked, price_per_mtok_in: Number(priceIn.value), price_per_mtok_out: Number(priceOut.value) };
          if (clearKey.box.checked) payload.api_key = '';
          else if (keyIn.value.trim()) payload.api_key = keyIn.value.trim();
          const r = await api('/api/settings/ai', { method: 'PUT', body: payload });
          keyIn.value = '';
          toast(r.warning ? 'Saved. ' + r.warning + '.' : r.running ? 'Saved. AI analysis is running.' : 'Saved. AI analysis is off.', r.warning ? 'warn' : 'ok', 6000);
          await load();
        });
      });
      test.addEventListener('click', () => act(test, async () => {
        result.textContent = 'Testing…';
        const r = await api('/api/settings/ai/test', { method: 'POST' });
        result.textContent = r.ok ? 'Connected in ' + (r.latency_ms < 1 ? '<1 ms' : fmtMs(r.latency_ms)) + (r.model_version ? ' (' + str(r.model_version) + ')' : '') + '.' : 'Failed: ' + str(r.error);
        result.className = 'hint ' + (r.ok ? 'ok-text' : 'err-text');
      }));
      reset.addEventListener('click', async () => {
        const yes = await modal({ title: 'Reset AI settings?', ok: 'Reset', danger: true, body: h('p', { text: 'The values from the config file apply again. A saved API key stays saved until you remove it.' }) });
        if (yes) act(reset, async () => { await api('/api/settings/ai', { method: 'DELETE' }); toast('AI settings reset to the config file.', 'ok'); await load(); });
      });
      c.body.appendChild(form);
      return c.el;
    }

    function challengeCard() {
      const ch = data.challenge;
      const c = card('Challenge page (Cloudflare Turnstile)', { actions: h('span', { class: 'badge plain', text: 'Policy v' + str(ch.policy_version) }) });
      const enabled = checkbox('Enable the challenge page', ch.enabled, 'Rules with action "challenge" need this. Turning it off fails if such rules exist.');
      const site = h('input', { type: 'text', value: str(ch.site_key), spellcheck: false, autocomplete: 'off', placeholder: 'Site key from the Cloudflare dashboard' });
      const secret = secretInput(ch.secret_key_set, 'A secret key');
      const path = h('input', { type: 'text', value: str(ch.challenge_path), spellcheck: false });
      const ttl = numInput(ch.cookie_ttl, 60, 2592000, 60);
      const rotate = checkbox('Issue a new cookie signing key', false, 'Every visitor who passed the challenge must pass it again.');
      const save = h('button', { type: 'submit', class: 'btn btn-primary', text: 'Save as new policy version' });
      const form = h('form', { class: 'settings-form' },
        enabled.el,
        h('div', { class: 'grid grid-2' }, field('Site key', site), field('Secret key', secret, 'Stored encrypted with the policy. Never shown again.')),
        h('div', { class: 'grid grid-2' }, field('Challenge path', path), field('Verified-visitor cookie lifetime (seconds)', ttl)),
        ch.cookie_secret_set ? rotate.el : h('p', { class: 'hint', text: 'A cookie signing key is generated automatically.' }),
        h('p', { class: 'hint', text: str(ch.note) }),
        h('div', { class: 'row form-actions' }, save));
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        act(save, async () => {
          const r = await api('/api/settings/challenge', { method: 'PUT', body: {
            enabled: enabled.box.checked, site_key: site.value.trim(), secret_key: secret.value.trim() || undefined,
            challenge_path: path.value.trim(), cookie_ttl: Number(ttl.value), rotate_cookie_secret: rotate.box.checked } });
          secret.value = '';
          changeResult(r, 'Challenge settings');
          await load();
        });
      });
      c.body.appendChild(form);
      return c.el;
    }

    function usersCard() {
      const wrap = h('div', { class: 'stack' });
      const c = card('Users & tokens');
      const list = h('div');
      c.body.appendChild(list);
      const name = h('input', { type: 'text', spellcheck: false, autocomplete: 'off', maxLength: 64, placeholder: 'e.g. alice' });
      const role = select([['viewer', 'Viewer: read only'], ['analyst', 'Analyst: labels, alerts, AI'], ['operator', 'Operator: + IP blocks'], ['admin', 'Admin: everything']], S.me && S.me.setup_mode ? 'admin' : 'analyst');
      const add = h('button', { type: 'submit', class: 'btn btn-primary', text: 'Create user' });
      const form = h('form', { class: 'settings-form row-form' }, field('Name', name), field('Role', role), h('div', { class: 'form-actions' }, add));
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        act(add, async () => {
          const r = await api('/api/users', { method: 'POST', body: { name: name.value.trim(), role: role.value } });
          name.value = '';
          await showTokenOnce(r.name, r.token, r.note);
          if (S.me && S.me.setup_mode && r.role === 'admin') {
            toast('Admin created. Sign in with its token; the setup token no longer works.', 'ok', 9000);
            logout('Setup finished. Sign in with the new admin token.');
            return;
          }
          await loadUsers();
        });
      });
      const addCard = card('Add a user', { sub: 'The token is shown once; only its hash is stored.' });
      addCard.body.appendChild(form);
      async function loadUsers() {
        list.replaceChildren(stateBox('loading', 'Loading users…'));
        const r = await api('/api/users');
        const users = Array.isArray(r.users) ? r.users : [];
        if (!users.length) { list.replaceChildren(stateBox('empty', 'No users yet. Create the first admin below.')); return; }
        list.replaceChildren(table([
          { label: 'Name', render: (u) => h('span', null, h('strong', { text: str(u.name) }), u.name === r.me ? h('span', { class: 'faint', text: ' (you)' }) : null) },
          { label: 'Role', render: (u) => {
            if (!u.editable || u.name === r.me) return h('span', { class: 'badge plain', text: str(u.role) });
            const s = select(['viewer', 'analyst', 'operator', 'admin'], u.role, { 'aria-label': 'Role of ' + str(u.name) });
            s.addEventListener('change', () => act(s, async () => { await api('/api/users/' + enc(u.name), { method: 'PUT', body: { role: s.value } }); toast('Role changed.', 'ok'); await loadUsers(); }));
            return s;
          } },
          { label: 'Source', render: (u) => h('span', { class: 'faint', text: u.source === 'config_file' ? 'config file' : 'dashboard' }) },
          { label: 'Created', render: (u) => u.created_ts ? h('span', null, timeEl(u.created_ts), h('span', { class: 'faint', text: ' by ' + str(u.created_by) })) : '—' },
          { label: '', cls: 'actions', render: (u) => {
            if (!u.editable) return h('span', { class: 'faint', text: 'edit in config' });
            const rot = h('button', { type: 'button', class: 'btn btn-sm', text: 'New token' });
            rot.addEventListener('click', async () => {
              const yes = await modal({ title: 'Issue a new token for ' + str(u.name) + '?', ok: 'Issue token', danger: true, body: h('p', { text: 'The current token stops working immediately.' }) });
              if (yes) act(rot, async () => { const t = await api('/api/users/' + enc(u.name) + '/rotate', { method: 'POST' }); await showTokenOnce(t.name, t.token, t.note); await loadUsers(); });
            });
            const del = h('button', { type: 'button', class: 'btn btn-sm btn-danger', text: 'Revoke' });
            del.disabled = u.name === r.me;
            del.addEventListener('click', async () => {
              const yes = await modal({ title: 'Revoke ' + str(u.name) + '?', ok: 'Revoke', danger: true, body: h('p', { text: 'The user can no longer sign in. Their past actions stay in the audit log.' }) });
              if (yes) act(del, async () => { await api('/api/users/' + enc(u.name), { method: 'DELETE' }); toast('Access revoked.', 'ok'); await loadUsers(); });
            });
            return h('span', { class: 'row' }, rot, del);
          } },
        ], users, { caption: 'Users' }));
      }
      loadUsers().catch((e) => { if (e.status !== 401) list.replaceChildren(stateBox('error', e.message)); });
      wrap.append(c.el, addCard.el);
      return wrap;
    }

    function storageCard() {
      const st = data.storage, v = st.values;
      const c = card('Event storage', { actions: sourceBadge2(st.source, st.updated) });
      const all = checkbox('Store every request', v.store_all_events, 'Cost 19–27% throughput in our benchmark. Statistics and alerts always count every request either way.');
      const rate = numInput(Math.round(v.benign_sample_rate * 10000) / 100, 0, 100, 0.1);
      const perClient = numInput(v.per_client_per_sec, 0, 100000);
      const days = numInput(v.retention_days, 1, 3650);
      const maxEv = numInput(v.max_events, 1000, 1000000000, 1000);
      const body = numInput(v.body_excerpt_bytes, 0, 65536, 256);
      const save = h('button', { type: 'submit', class: 'btn btn-primary', text: 'Save' });
      const reset = h('button', { type: 'button', class: 'btn', text: 'Reset to config file' });
      const form = h('form', { class: 'settings-form' },
        all.el,
        h('div', { class: 'grid grid-3' },
          field('Ordinary requests stored (%)', rate, 'Requests with a rule match, an anomaly or a 5xx are always stored.'),
          field('Stored events per client per second', perClient, '0 means no limit. Keeps floods from filling the store.'),
          field('Body excerpt kept for rule matches (bytes)', body)),
        h('div', { class: 'grid grid-3' }, field('Keep events for (days)', days), field('Keep at most (events)', maxEv)),
        h('div', { class: 'row form-actions' }, save, st.source === 'dashboard' ? reset : null));
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        act(save, async () => {
          await api('/api/settings/storage', { method: 'PUT', body: { store_all_events: all.box.checked, benign_sample_rate: Number(rate.value) / 100,
            per_client_per_sec: Number(perClient.value), retention_days: Number(days.value), max_events: Number(maxEv.value), body_excerpt_bytes: Number(body.value) } });
          toast('Storage settings saved and applied.', 'ok');
          await load();
        });
      });
      reset.addEventListener('click', () => act(reset, async () => { await api('/api/settings/storage', { method: 'DELETE' }); toast('Storage settings reset to the config file.', 'ok'); await load(); }));
      c.body.appendChild(form);
      return c.el;
    }

    function securityCard() {
      const s = data.security;
      const c = card('Security of stored settings');
      c.body.appendChild(kv([
        ['Encryption', str(s.encryption)],
        ['Secret key from', str(s.secret_key_source)],
        ['Encrypted', 'AI API key, Turnstile secret, cookie signing key, every stored policy version, pending changes'],
        ['Hashed (SHA-256)', 'Admin tokens; a token is shown once when created or rotated'],
        ['Never sent to the browser', 'Secret values; this page only shows whether one is set'],
        ['First-run setup', s.setup_mode ? 'Active: create an admin to end it' : 'Finished'],
      ]));
      c.body.appendChild(h('p', { class: 'hint', text: 'Back up the secret key file separately from the database. Without it, saved secrets cannot be read and must be entered again.' }));
      return c.el;
    }

    load();
  };

  // ------------------------------------------------------------------ theme
  function effectiveTheme() {
    const t = document.documentElement.dataset.theme;
    if (t === 'light' || t === 'dark') return t;
    return window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  function syncThemeButton() {
    const t = effectiveTheme();
    $('theme-icon').setAttribute('href', t === 'dark' ? '#i-sun' : '#i-moon');
    $('theme-toggle').setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    $('theme-toggle').title = $('theme-toggle').getAttribute('aria-label');
  }
  function setTheme(t) {
    document.documentElement.dataset.theme = t;
    store.set('localStorage', 'os-theme', t);
    syncThemeButton();
    window.dispatchEvent(new Event('os-theme'));
  }
  (function initTheme() {
    const saved = store.get('localStorage', 'os-theme');
    if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
    syncThemeButton();
    if (window.matchMedia) {
      const mq = matchMedia('(prefers-color-scheme: light)');
      const fn = () => { if (!document.documentElement.dataset.theme) { syncThemeButton(); window.dispatchEvent(new Event('os-theme')); } };
      if (mq.addEventListener) mq.addEventListener('change', fn);
    }
  })();
  $('theme-toggle').addEventListener('click', () => setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark'));

  // ------------------------------------------------------------------ auth / shell
  function showLogin(msg) {
    $('app').hidden = true;
    $('login').hidden = false;
    $('login-error').textContent = msg || '';
    $('login-submit').disabled = false;
    $('login-token').value = '';
    document.title = 'Sign in · OpenShield';
    $('login-token').focus();
  }
  function enterApp() {
    $('login').hidden = true;
    $('app').hidden = false;
    $('user-name').textContent = str(S.me.name) || 'unknown';
    $('user-role').textContent = str(S.me.role) || '?';
    $('user-chip').title = 'Signed in as ' + str(S.me.name) + ' (' + str(S.me.role) + ')';
    for (const a of document.querySelectorAll('#sidenav a[data-min-role]')) a.hidden = !can(a.dataset.minRole);
    $('setup-chip').hidden = !S.me.setup_mode;
    streamStart();
    refreshAlertCount();
    refreshDetectionMode();
    if (S.me.setup_mode && parseHash().name !== 'settings') { go('settings', new URLSearchParams('tab=users')); return; }
    route();
  }
  function logout(msg) {
    const was = !!S.token;
    S.token = null; S.me = null;
    store.del('sessionStorage', 'os-token');
    streamStop();
    teardownView();
    closeDrawer();
    if ($('modal').open) $('modal').close();
    $('view').replaceChildren();
    S.alertsOpen = 0; renderAlertCount();
    $('rps-val').textContent = '–';
    if (was || msg) showLogin(msg);
  }
  async function validateToken(token) {
    let res;
    try { res = await fetch('/api/me', { headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' }, cache: 'no-store', credentials: 'omit' }); } catch (e) { return { error: 'Cannot reach the admin server.' }; }
    if (res.status === 401 || res.status === 403) return { error: 'That token was not accepted.' };
    if (res.status === 429) return { error: 'Too many failed attempts from this address. Wait a minute and try again.' };
    if (!res.ok) return { error: 'Sign-in failed (HTTP ' + res.status + ').' };
    try {
      const me = await res.json();
      if (!me || RANK[me.role] === undefined) return { error: 'The server returned an unknown role.' };
      return { me };
    } catch (e) { return { error: 'The server returned malformed JSON.' }; }
  }
  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const token = $('login-token').value.trim();
    if (!token) { $('login-error').textContent = 'Enter your admin token.'; return; }
    $('login-submit').disabled = true;
    $('login-error').textContent = '';
    const r = await validateToken(token);
    $('login-submit').disabled = false;
    if (r.error) { $('login-error').textContent = r.error; $('login-token').select(); return; }
    S.token = token; S.me = r.me;
    store.set('sessionStorage', 'os-token', token);
    $('login-token').value = '';
    enterApp();
  });
  $('login-reveal').addEventListener('click', () => {
    const i = $('login-token');
    const show = i.type === 'password';
    i.type = show ? 'text' : 'password';
    $('login-reveal').setAttribute('aria-pressed', String(show));
    $('login-reveal').setAttribute('aria-label', show ? 'Hide token' : 'Show token');
  });
  $('logout').addEventListener('click', () => logout('Signed out.'));
  $('nav-toggle').addEventListener('click', () => setNav(!$('sidenav').classList.contains('open')));
  $('nav-scrim').addEventListener('click', () => setNav(false));
  window.addEventListener('hashchange', route);

  (async function boot() {
    const token = store.get('sessionStorage', 'os-token');
    if (!token) { showLogin(); return; }
    const r = await validateToken(token);
    if (r.error) { store.del('sessionStorage', 'os-token'); showLogin(r.error === 'That token was not accepted.' ? 'Your session expired. Sign in again.' : r.error); return; }
    S.token = token; S.me = r.me;
    enterApp();
  })();
})();
