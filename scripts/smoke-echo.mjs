#!/usr/bin/env node
// Loopback sink for the Worker smoke test: records every request and exposes
// them at GET /_requests so the test can assert deliveries actually arrived.
import http from 'node:http';

const port = Number(process.env.PORT);
if (!port) { console.error('PORT is required'); process.exit(2); }
const requests = [];

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    requests.push({ method: req.method, path: req.url, body, headers: req.headers });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(req.url === '/_requests' ? JSON.stringify(requests.filter(r => r.path !== '/_requests')) : '{"ok":true}');
  });
});
server.listen(port, '127.0.0.1', () => console.log(`echo listening on ${port}`));
