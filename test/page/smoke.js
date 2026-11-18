'use strict';
// Renders web/settings.js against a fake host and checks the flows end to end.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { textOf, findAll, fire, makeDocument } = require('./dom_stub');

const SRC = fs.readFileSync(path.join(__dirname, '..', '..', 'web', 'settings.js'), 'utf8');
const MGMT = 'mgmt-secret';
const P = '/v0/management/plugins/key-access';
const NL = String.fromCharCode(10);
const NUL = String.fromCharCode(0);
const POLICY_KEYS = ['caller_scope', 'name', 'allow_models', 'deny_models', 'allow_profiles', 'deny_profiles'];
const DOC_KEYS = ['version', 'unconfigured_key', 'policies'];
let failures = 0;

const scopeOf = (key) => crypto.createHash('sha256').update('cli-proxy-api:caller-scope:v1' + NUL + key, 'utf8').digest('hex');
const tick = (ms) => new Promise((resolve) => setTimeout(resolve, ms || 20));
function check(label, ok, detail) {
  console.log((ok ? 'PASS ' : 'FAIL ') + label);
  if (!ok) { failures++; if (detail !== undefined) console.log('  ' + detail); }
}

function makeServer(opts) {
  opts = opts || {};
  const s = { calls: [], revision: 1, put412: false, persistent: false, policyFile: '', hostSchema: opts.hostSchema || 7 };
  s.doc = { version: 1, unconfigured_key: 'allow', policies: [
    { caller_scope: scopeOf('sk-test-abcdef'), name: 'alice', allow_models: [], deny_models: ['gpt-*'], allow_profiles: [], deny_profiles: [] },
    { caller_scope: scopeOf('gone-key'), name: '', allow_models: [], deny_models: [], allow_profiles: ['claude:*'], deny_profiles: [] },
  ] };
  s.fetch = async (url, init) => {
    const method = init.method;
    const body = init.body ? JSON.parse(init.body) : undefined;
    s.calls.push({ method, url, headers: init.headers, body });
    const res = (status, data, etag) => ({
      ok: status < 400, status, statusText: String(status),
      text: async () => JSON.stringify(data),
      headers: { get: (n) => (n === 'ETag' ? etag || '' : null) },
    });
    if (init.headers.Authorization !== 'Bearer ' + MGMT) return res(401, { error: 'unauthorized' });
    if (method === 'GET' && url === P + '/policies') return res(200, { policy: s.doc, revision: s.revision }, '"rev-' + s.revision + '"');
    if (method === 'GET' && url === P + '/status') {
      return res(200, { version: '0.1.0', policy_count: s.doc.policies.length, persistent_updates: s.persistent, policy_file: s.policyFile, fail_closed: false, host_schema_version: s.hostSchema });
    }
    if (method === 'GET' && url === '/v0/management/api-keys') return res(200, { 'api-keys': ['sk-test-abcdef', 'k2'] });
    if (method === 'PUT' && url === P + '/policies') {
      if (s.put412) { s.put412 = false; return res(412, { error: 'policy changed since it was loaded' }); }
      s.doc = body;
      s.revision++;
      return res(200, { ok: true }, '"rev-' + s.revision + '"');
    }
    if (method === 'GET' && url === '/v0/management/plugins') return res(200, { plugins_dir: '/opt/cpa/plug&amp;ins', plugins: [] });
    if (method === 'POST' && url === P + '/initialize-storage') {
      s.initDir = body.plugins_dir;
      const file = body.plugins_dir + '/key-access/policies.yaml';
      return res(201, { created: true, policy_file: opts.escapeInit ? file.replace(/&/g, '&amp;') : file });
    }
    if (method === 'PATCH' && url === P + '/config') {
      s.patch = body;
      s.persistent = true;
      s.policyFile = body.policy_file;
      return res(200, { status: 'ok' });
    }
    return res(404, { error: 'no route ' + method + ' ' + url });
  };
  return s;
}

async function boot(server) {
  const doc = makeDocument();
  new Function('document', 'fetch', 'setTimeout', SRC)(doc, server.fetch, setTimeout);
  return doc;
}

const btn = (doc, label) => findAll(doc.app, (n) => n.tag === 'button' && textOf(n) === label)[0];
const rows = (doc) => findAll(doc.app, (n) => (n.className || '').split(' ').includes('row'));
const textareas = (doc) => findAll(doc.app, (n) => n.tag === 'textarea');

async function login(doc, key) {
  findAll(doc.app, (n) => n.tag === 'input')[0].value = key;
  fire(btn(doc, 'Connect'), 'click');
  await tick();
}

async function main() {
  {
    const doc = await boot(makeServer());
    check('login form is shown first', !!btn(doc, 'Connect'));
    await login(doc, 'wrong');
    check('wrong management key is rejected', textOf(doc.app).includes('Management key rejected.'), textOf(doc.app));
  }

  const server = makeServer();
  const doc = await boot(server);
  await login(doc, MGMT);
  const text = () => textOf(doc.app);
  check('page renders after login', text().includes('Key Access'), text());
  check('keys are listed masked', text().includes('sk-t***cdef') && text().includes('k2***'), text());
  check('raw keys never reach the page', !text().includes('sk-test-abcdef'));
  check('policy name and rule count are shown', text().includes('alice') && text().includes('1 rules'), text());
  check('keys removed from CPA are flagged', text().includes('removed key'), text());
  check('persistence is offered while memory only', !!btn(doc, 'Save policies to disk'));

  fire(rows(doc)[0], 'click');
  check('editor shows four rule boxes', textareas(doc).length === 4, String(textareas(doc).length));
  check('existing deny rule is loaded', textareas(doc)[1].value === 'gpt-*', textareas(doc)[1].value);
  check('save starts disabled', btn(doc, 'Save').disabled === true);

  const box = textareas(doc)[1];
  box.value = ['gpt-5', ' gpt-4 ', '', ''].join(NL);
  fire(box, 'input');
  check('editing enables save', btn(doc, 'Save').disabled === false);
  fire(btn(doc, 'Save'), 'click');
  await tick(60);
  const put = server.calls.filter((c) => c.method === 'PUT');
  check('save sends one PUT with the loaded ETag', put.length === 1 && put[0].headers['If-Match'] === '"rev-1"', JSON.stringify(put[0] && put[0].headers));
  check('rules are trimmed and blank lines dropped', JSON.stringify(put[0].body.policies[0].deny_models) === JSON.stringify(['gpt-5', 'gpt-4']), JSON.stringify(put[0].body));
  check('PUT body has only fields the plugin accepts', Object.keys(put[0].body).every((k) => DOC_KEYS.includes(k)) && put[0].body.policies.every((p) => Object.keys(p).every((k) => POLICY_KEYS.includes(k))), JSON.stringify(put[0].body));
  check('saved notice is shown', text().includes('Saved.'), text());

  fire(rows(doc)[0], 'click');
  const box2 = textareas(doc)[1];
  box2.value = 'x';
  fire(box2, 'input');
  server.put412 = true;
  fire(btn(doc, 'Save'), 'click');
  await tick(60);
  check('a stale save reports a conflict', text().includes('changed elsewhere'), text());

  fire(rows(doc)[1], 'click');
  check('a key without a policy offers to create one', !!btn(doc, 'Create policy'));
  fire(btn(doc, 'Create policy'), 'click');
  check('new policy gets an editor and a remove button', !!btn(doc, 'Remove policy') && textareas(doc).length === 4);

  fire(findAll(doc.app, (n) => n.tag === 'select')[0], 'change', { target: { value: 'deny' } });
  fire(btn(doc, 'Save'), 'click');
  await tick(60);
  const last = server.calls.filter((c) => c.method === 'PUT').pop().body;
  check('new policy is saved with the derived scope', last.policies.some((p) => p.caller_scope === scopeOf('k2')), JSON.stringify(last));
  check('unconfigured_key deny is saved', last.unconfigured_key === 'deny', last.unconfigured_key);

  for (const [schema, escapeInit] of [[7, false], [5, true]]) {
    const s = makeServer({ hostSchema: schema, escapeInit });
    const d = await boot(s);
    await login(d, MGMT);
    fire(btn(d, 'Save policies to disk'), 'click');
    await tick(900);
    const want = '/opt/cpa/plug&ins/key-access/policies.yaml';
    const tag = 'persistence (host schema ' + schema + ')';
    check(tag + ' unescapes plugins_dir', s.initDir === '/opt/cpa/plug&ins', s.initDir);
    check(tag + ' patches policy_file', !!s.patch && s.patch.policy_file === want, JSON.stringify(s.patch));
    check(tag + ' switches the status to saved', textOf(d.app).includes('saved to ' + want) && !btn(d, 'Save policies to disk'), textOf(d.app));
  }

  {
    const s = makeServer();
    const d = await boot(s);
    await login(d, MGMT);
    fire(rows(d)[0], 'click');
    const b = textareas(d)[0];
    b.value = 'claude-*';
    fire(b, 'input');
    fire(btn(d, 'Save policies to disk'), 'click');
    await tick(60);
    check('persistence refuses while edits are unsaved', textOf(d.app).includes('Save or reload your edits first.') && !s.calls.some((c) => c.url.endsWith('initialize-storage')), textOf(d.app));
  }

  console.log(failures ? 'FAILED: ' + failures : 'ALL PASS');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.log('FAIL harness crashed: ' + err.stack); process.exit(1); });
