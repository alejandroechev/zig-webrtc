const { WebSocketServer } = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');

// --- HTTP server to serve the browser client ---
const httpServer = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(path.join(__dirname, 'browser-client.html')));
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});
httpServer.listen(8081, () => console.log('Browser client at http://localhost:8081'));

// --- WebSocket signaling server ---
const wss = new WebSocketServer({ port: 8080 });
const peers = new Map();

wss.on('connection', (ws) => {
  const peerId = peers.size === 0 ? 'zig' : 'browser';
  peers.set(peerId, ws);
  console.log(`${peerId} connected`);

  ws.on('message', (data) => {
    const msg = JSON.parse(data);
    console.log(`${peerId} -> ${msg.type}`);

    // Relay to the other peer
    const otherId = peerId === 'zig' ? 'browser' : 'zig';
    const other = peers.get(otherId);
    if (other && other.readyState === 1) {
      other.send(data.toString());
    }
  });

  ws.on('close', () => {
    peers.delete(peerId);
    console.log(`${peerId} disconnected`);
  });
});

console.log('Signaling server on ws://localhost:8080');
