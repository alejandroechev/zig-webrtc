const { WebSocketServer } = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');

// --- HTTP server to serve the browser client ---
const httpServer = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(path.join(__dirname, 'browser-client.html')));
  } else if (req.url === '/audio-test') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(path.join(__dirname, 'browser-audio-test.html')));
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});
httpServer.listen(8081, () => console.log('Browser client at http://localhost:8081'));

// --- WebSocket signaling server ---
const wss = new WebSocketServer({ port: 8080 });
const peers = new Map();
const queued = new Map(); // messages queued before other peer connects

wss.on('connection', (ws, req) => {
  // Allow explicit role via query param: ws://localhost:8080?role=zig
  const url = new URL(req.url, 'http://localhost');
  const role = url.searchParams.get('role');
  const peerId = role || (peers.has('zig') ? 'browser' : 'zig');
  peers.set(peerId, ws);
  console.log(`${peerId} connected (${peers.size}/2 peers)`);

  // Flush any queued messages for this peer
  const pending = queued.get(peerId) || [];
  for (const msg of pending) {
    ws.send(msg);
    console.log(`${peerId} <- (queued) ${JSON.parse(msg).type}`);
  }
  queued.delete(peerId);

  ws.on('message', (data) => {
    const msg = JSON.parse(data);
    console.log(`${peerId} -> ${msg.type}`);

    const otherId = peerId === 'zig' ? 'browser' : 'zig';
    const other = peers.get(otherId);
    if (other && other.readyState === 1) {
      other.send(data.toString());
    } else {
      // Queue for when the other peer connects
      if (!queued.has(otherId)) queued.set(otherId, []);
      queued.get(otherId).push(data.toString());
      console.log(`${peerId} -> ${msg.type} (queued for ${otherId})`);
    }
  });

  ws.on('close', () => {
    peers.delete(peerId);
    console.log(`${peerId} disconnected`);
  });
});

console.log('Signaling server on ws://localhost:8080');
