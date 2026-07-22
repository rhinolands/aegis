#!/usr/bin/env node
// Tiny local HTTP server standing in for a real MCP tool backend, used only by
// scripts/demo.sh. Its job is to prove two things to a stranger watching the
// demo:
//
//   1. the gateway actually calls the destination it resolved server-side
//      (echoes back whatever operation/args it received), and
//   2. the gateway injected the scoped backend credential as the upstream
//      Authorization header — a credential this script's caller (the demo
//      agent) never held and never sent itself.
//
// Point 2 is the load-bearing one: the demo agent authenticates to the
// gateway with its own x-api-key, never with this upstream's bearer token.
// If `authSeen` comes back true and `authPreview` shows a token, that token
// arrived here solely because the gateway injected it.
import { createServer } from 'node:http';

const port = Number(process.env.ECHO_PORT ?? 7070);

const server = createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    let echoed;
    try {
      echoed = JSON.parse(body || '{}');
    } catch {
      echoed = { $unparseable: body };
    }
    const authHeader = req.headers.authorization ?? '';
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      echoed,
      authSeen: !!authHeader,
      // First 16 chars only — enough to show a real bearer token arrived
      // without printing the whole secret in demo output/logs.
      authPreview: authHeader ? `${authHeader.slice(0, 16)}...` : null,
    }));
  });
});

server.listen(port, () => {
  console.log(`echo upstream listening on :${port}`);
});

const shutdown = () => {
  server.close(() => process.exit(0));
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
