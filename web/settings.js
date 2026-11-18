'use strict';

// == SECTION: state and helpers
const BASE = '/v0/management';
const PLUGIN = BASE + '/plugins/key-access';
const state = { mgmt: '', keys: [], doc: null, etag: '', status: null, selected: '', dirty: false, error: '' };
const app = document.getElementById('app');

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (name === 'class') el.className = value;
    else if (name.startsWith('on')) el.addEventListener(name.slice(2), value);
    else if (value !== false && value != null) el.setAttribute(name, value);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : String(kid));
  return el;
}

const mask = (key) => (key.length <= 10 ? key.slice(0, 2) + '***' : key.slice(0, 4) + '***' + key.slice(-4));

// == SECTION: sha256 (pure JS: crypto.subtle is unavailable on plain-http origins)
const SHA = (() => {
  const K = [];
  const H0 = [];
  for (let n = 2, c = 0; c < 64; n++) {
    let prime = true;
    for (let d = 2; d * d <= n; d++) {
      if (n % d === 0) { prime = false; break; }
    }
    if (!prime) continue;
    if (c < 8) H0[c] = (Math.pow(n, 0.5) * 4294967296) | 0;
    K[c++] = (Math.pow(n, 1 / 3) * 4294967296) | 0;
  }
  return { K, H0 };
})();

function sha256Hex(text) {
  const msg = new TextEncoder().encode(text);
  const len = msg.length;
  const total = (((len + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor(len / 536870912));
  dv.setUint32(total - 4, (len << 3) >>> 0);
  const hash = SHA.H0.slice();
  const w = new Array(64);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = hash;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & g)) + SHA.K[i] + w[i]) | 0;
      const t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    [a, b, c, d, e, f, g, hh].forEach((v, i) => { hash[i] = (hash[i] + v) | 0; });
  }
  return hash.map((v) => (v >>> 0).toString(16).padStart(8, '0')).join('');
}

// Must match the host derivation (and callerScopeOf in policy.go).
const scopeOf = (key) => sha256Hex('cli-proxy-api:caller-scope:v1\u0000' + key.trim());

// == SECTION: api and data loading
async function api(method, path, body, headers) {
  const init = { method, cache: 'no-store', headers: Object.assign({ Authorization: 'Bearer ' + state.mgmt }, headers || {}) };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, init);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { error: text }; }
  if (!res.ok) {
    const err = new Error((data && data.error && data.error.message) || (data && data.error) || res.statusText);
    err.status = res.status;
    throw err;
  }
  return { data, etag: res.headers.get('ETag') || '' };
}

async function loadAll() {
  const [pol, st, keys] = await Promise.all([
    api('GET', PLUGIN + '/policies'),
    api('GET', PLUGIN + '/status'),
    api('GET', BASE + '/api-keys'),
  ]);
  state.doc = pol.data.policy;
  state.etag = pol.etag;
  state.status = st.data;
  const raw = Array.isArray(keys.data) ? keys.data : (keys.data && (keys.data['api-keys'] || keys.data.api_keys)) || [];
  state.keys = raw
    .filter((k) => typeof k === 'string' && k.trim())
    .map((k) => ({ scope: scopeOf(k), label: mask(k.trim()) }));
  state.dirty = false;
}

// == SECTION: views
function renderLogin() {
  const input = h('input', { type: 'password', placeholder: 'Management key', autocomplete: 'off' });
  const error = h('p', { class: 'error' }, state.error);
  const connect = async () => {
    state.mgmt = input.value.trim();
    state.error = '';
    try {
      await loadAll();
      render();
    } catch (err) {
      state.mgmt = '';
      error.textContent = err.status === 401 || err.status === 403 ? 'Management key rejected.' : 'Load failed: ' + err.message;
    }
  };
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') connect(); });
  return h('section', { class: 'card login' },
    h('h2', {}, 'Connect'),
    h('p', { class: 'muted' }, 'The management key stays in this page only and is never stored.'),
    input, h('button', { onclick: connect }, 'Connect'), error);
}

function render() {
  if (!state.mgmt || !state.doc) { app.replaceChildren(renderLogin()); return; }
  app.replaceChildren(h('h1', {}, 'Key Access'), renderStatus(), h('div', { class: 'layout' }, renderList(), renderEditor()));
}

function renderStatus() {
  const s = state.status || {};
  const where = s.persistent_updates ? 'saved to ' + s.policy_file : 'memory only (storage not initialized)';
  const line = h('p', { class: 'muted' }, 'v' + s.version + ' - ' + s.policy_count + ' policies - ' + where + (s.fail_closed ? ' - FAIL CLOSED: ' + s.last_error : ''));
  if (s.persistent_updates || s.fail_closed) return line;
  const enable = h('button', { class: 'secondary', onclick: async () => {
    enable.disabled = true;
    try {
      await enablePersistence();
      state.error = '';
      state.notice = 'Policies are now saved to disk.';
    } catch (err) {
      state.error = err.message;
    }
    render();
  } }, 'Save policies to disk');
  return h('div', {}, line, enable);
}

// == SECTION: storage initialization
// GET /plugins HTML-escapes plugins_dir; decode it in one pass so an escaped ampersand is not decoded twice.
const ENTITIES = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&#34;': String.fromCharCode(34), '&#39;': String.fromCharCode(39) };
const unescapeHtml = (text) => text.replace(/&(?:lt|gt|amp|#34|#39);/g, (m) => ENTITIES[m]);

async function enablePersistence() {
  if (state.dirty) throw new Error('Save or reload your edits first.');
  const list = await api('GET', BASE + '/plugins');
  const dir = unescapeHtml(String((list.data && list.data.plugins_dir) || ''));
  if (!dir) throw new Error('The host did not report plugins_dir.');
  const init = await api('POST', PLUGIN + '/initialize-storage', { plugins_dir: dir });
  // Plugin responses are only HTML-escaped by hosts older than RPC schema 6.
  const raw = String(init.data.policy_file || '');
  const file = state.status.host_schema_version >= 6 ? raw : unescapeHtml(raw);
  await api('PATCH', PLUGIN + '/config', { policy_file: file });
  // The host reconfigures the plugin asynchronously after saving; wait for it.
  for (let i = 0; i < 10; i++) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    await loadAll();
    if (state.status.persistent_updates) return;
  }
  throw new Error('policy_file was saved but the plugin has not reloaded it yet. Reload this page shortly.');
}

// == SECTION: key list
function policyFor(scope) {
  return state.doc.policies.find((p) => p.caller_scope === scope);
}

function ruleCount(p) {
  return p ? p.allow_models.length + p.deny_models.length + p.allow_profiles.length + p.deny_profiles.length : 0;
}

function listEntries() {
  const known = new Set(state.keys.map((k) => k.scope));
  const entries = state.keys.map((k) => ({ scope: k.scope, label: k.label }));
  for (const p of state.doc.policies) {
    if (!known.has(p.caller_scope)) entries.push({ scope: p.caller_scope, label: 'removed key ' + p.caller_scope.slice(0, 8), orphan: true });
  }
  return entries;
}

function renderList() {
  const unconfigured = h('select', { onchange: (e) => { state.doc.unconfigured_key = e.target.value; state.dirty = true; render(); } },
    h('option', { value: 'allow', selected: state.doc.unconfigured_key !== 'deny' }, 'allow'),
    h('option', { value: 'deny', selected: state.doc.unconfigured_key === 'deny' }, 'deny'));
  const rows = listEntries().map((entry) => {
    const p = policyFor(entry.scope);
    const n = ruleCount(p);
    const name = p && p.name ? p.name + ' ' : '';
    return h('div', { class: 'row' + (state.selected === entry.scope ? ' active' : ''), onclick: () => { state.selected = entry.scope; render(); } },
      name + entry.label, ' ', h('span', { class: 'chip' }, entry.orphan ? 'removed' : n ? n + ' rules' : 'no policy'));
  });
  return h('aside', { class: 'card list' }, h('h2', {}, 'API keys'), rows.length ? rows : h('p', { class: 'muted' }, 'No API keys found in CPA.'),
    h('h2', {}, 'Keys without a policy'), unconfigured);
}

// == SECTION: policy editor
const FIELDS = [
  ['allow_models', 'Allowed models', 'Whitelist when non-empty. Empty allows every model that is not denied.'],
  ['deny_models', 'Denied models', 'Always wins over the allow list. * matches any run, ? one character.'],
  ['allow_profiles', 'Allowed channels', 'Upstream auth IDs such as claude:* or codex:apikey:abc123. Whitelist when non-empty.'],
  ['deny_profiles', 'Denied channels', 'Always wins over the allow list.'],
];

const toLines = (text) => text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

function markDirty() {
  state.dirty = true;
  const save = document.getElementById('ka-save');
  if (save) save.disabled = false;
}

function saveBar() {
  const msg = h('span', { class: state.error ? 'error' : 'ok' }, state.error || state.notice || '');
  state.notice = '';
  const save = h('button', { id: 'ka-save', disabled: !state.dirty, onclick: async () => {
    save.disabled = true;
    try {
      await api('PUT', PLUGIN + '/policies', state.doc, state.etag ? { 'If-Match': state.etag } : {});
      await loadAll();
      state.error = '';
      state.notice = 'Saved.';
    } catch (err) {
      state.error = err.status === 412 ? 'The policy changed elsewhere. Reload and redo your edit.' : 'Save failed: ' + err.message;
    }
    render();
  } }, 'Save');
  const reload = h('button', { class: 'secondary', onclick: async () => {
    try { await loadAll(); state.error = ''; } catch (err) { state.error = 'Reload failed: ' + err.message; }
    render();
  } }, 'Reload');
  return h('div', { class: 'bar' }, save, reload, msg);
}

function renderEditor() {
  const box = h('section', { class: 'card editor' }, h('h2', {}, 'Policy'));
  const entry = listEntries().find((e) => e.scope === state.selected);
  if (!entry) {
    box.append(h('p', { class: 'muted' }, 'Select a key.'), saveBar());
    return box;
  }
  const p = policyFor(entry.scope);
  box.append(h('p', { class: 'muted' }, entry.label + ' (' + entry.scope.slice(0, 12) + '...)'));
  if (!p) {
    const fallback = state.doc.unconfigured_key === 'deny' ? 'it is denied.' : 'it can use every model and channel.';
    box.append(h('p', { class: 'muted' }, 'No policy: ' + fallback),
      h('button', { onclick: () => {
        state.doc.policies.push({ caller_scope: entry.scope, name: '', allow_models: [], deny_models: [], allow_profiles: [], deny_profiles: [] });
        markDirty();
        render();
      } }, 'Create policy'), saveBar());
    return box;
  }
  const name = h('input', { type: 'text', placeholder: 'Label, e.g. alice-laptop', value: p.name || '', oninput: (e) => { p.name = e.target.value; markDirty(); } });
  box.append(h('label', {}, 'Name'), name);
  const grid = h('div', { class: 'grid2' });
  for (const [field, title, hint] of FIELDS) {
    const area = h('textarea', { spellcheck: 'false', oninput: (e) => { p[field] = toLines(e.target.value); markDirty(); } }, (p[field] || []).join('\n'));
    grid.append(h('div', {}, h('label', {}, title), area, h('p', { class: 'muted' }, hint)));
  }
  box.append(grid, h('button', { class: 'secondary', onclick: () => {
    state.doc.policies = state.doc.policies.filter((x) => x !== p);
    markDirty();
    render();
  } }, 'Remove policy'), saveBar());
  return box;
}

// == SECTION: init
render();
