'use strict';
// Fake OpenAI-compatible upstream for the end-to-end test.
// Usage: node fake_upstream.js <name> <port>
// Every completion says which upstream served it; GET /_hits lists what this upstream received.
const http = require('http');
const name = process.argv[2];
const port = Number(process.argv[3]);
const hits = [];

http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/_hits') {
      res.end(JSON.stringify(hits));
      return;
    }
    if (req.method === 'GET' && req.url.endsWith('/models')) {
      res.end(JSON.stringify({ object: 'list', data: [{ id: 'm-a', object: 'model' }, { id: 'm-b', object: 'model' }] }));
      return;
    }
    let model = '';
    let stream = false;
    try { const parsed = JSON.parse(body); model = parsed.model || ''; stream = !!parsed.stream; } catch (err) { model = ''; }
    hits.push({ url: req.url, model, stream });
    if (stream) {
      const chunk = (delta, finish) => 'data: ' + JSON.stringify({ id: 'fake-' + hits.length, object: 'chat.completion.chunk', created: 1, model, choices: [{ index: 0, delta, finish_reason: finish }] }) + '\n\n';
      res.setHeader('Content-Type', 'text/event-stream');
      res.write(chunk({ role: 'assistant', content: 'served-by:' + name }, null));
      res.write(chunk({}, 'stop'));
      res.end('data: [DONE]\n\n');
      return;
    }
    res.end(JSON.stringify({
      id: 'fake-' + hits.length,
      object: 'chat.completion',
      created: 1,
      model,
      choices: [{ index: 0, message: { role: 'assistant', content: 'served-by:' + name }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }));
  });
}).listen(port, '127.0.0.1', () => console.log(name + ' listening on ' + port));
