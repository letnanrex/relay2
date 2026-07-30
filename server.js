import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import crypto from 'crypto';

// ==========================================
// KONFIGURASI KEAMANAN & RELAY
// ==========================================
const PORT = process.env.PORT || 3000;
const TOKEN = process.env.TOKEN || 'RexForYou';

// Batasan Keamanan (Proteksi DoS & Memori)
const MAX_PAYLOAD_SIZE = 1024 * 50; // Maks 50KB per pesan (Cegah Overload RAM)
const MAX_MSGS_PER_SEC = 20;        // Maks 20 pesan/detik per koneksi (Rate Limit)

const server = createServer();
const wss = new WebSocketServer({ 
    noServer: true, 
    maxPayload: MAX_PAYLOAD_SIZE 
});

const plugins = new Map();
const clis = new Set();

// 🛡️ FITUR KEAMANAN 1: Mencegah Timing Attacks pada pencocokan Token
function secureTokenCompare(clientToken, serverToken) {
    if (!clientToken || !serverToken) return false;
    const bufA = Buffer.from(clientToken);
    const bufB = Buffer.from(serverToken);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const clientToken = req.headers['x-bridge-token'] || url.searchParams.get('token');
    
    // Validasi token yang lebih aman
    if (!secureTokenCompare(clientToken, TOKEN)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req, url);
    });
});

wss.on('connection', (ws, req, url) => {
    // 🛡️ FITUR KEAMANAN 2: Setup Heartbeat (Mencegah Zombie Connections)
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    // 🛡️ FITUR KEAMANAN 3: Sederhana Rate Limiter per Koneksi
    let messageCount = 0;
    const rateLimiter = setInterval(() => { messageCount = 0; }, 1000);

    const role = url.searchParams.get('role'); 
    let rawServerName = url.searchParams.get('server');

    if (role === 'cli') {
        clis.add(ws);
        console.log(`[Relay] ✨ Aplikasi CLI Admin terhubung. (IP: ${req.socket.remoteAddress})`);
        
        ws.send(JSON.stringify({ type: '_relay_info', servers: Array.from(plugins.keys()) }));

        ws.on('message', (msg) => {
            if (++messageCount > MAX_MSGS_PER_SEC) return; // Drop spam pesan

            try {
                const data = JSON.parse(msg);
                // 🛡️ FITUR KEAMANAN 4: Validasi Tipe Data ketat (Cegah inject tipe data aneh)
                if (data && typeof data === 'object' && data.action === 'forward') {
                    const targetName = String(data.server); // Paksa ubah ke String
                    if (plugins.has(targetName) && data.payload && typeof data.payload === 'object') {
                        plugins.get(targetName).send(JSON.stringify(data.payload));
                    }
                }
            } catch(e) {} // Abaikan crash jika json cacat
        });

        ws.on('close', () => {
            clearInterval(rateLimiter);
            clis.delete(ws);
        });

    } else {
        // 🛡️ FITUR KEAMANAN 5: Sanitasi Nama Server (Cegah XSS/Karakter Ilegal)
        const name = String(rawServerName || 'Unknown')
                        .replace(/[^a-zA-Z0-9_\- ]/g, '') // Hanya izinkan alfanumerik, spasi, _, dan -
                        .substring(0, 32) || 'Unknown';

        // 🛡️ FITUR KEAMANAN 6: Pencegahan Konflik / Session Hijacking
        if (plugins.has(name)) {
            // Jika ada server dengan nama sama mencoba masuk, tendang yang lama
            plugins.get(name).close(1008, 'Koneksi digantikan oleh sesi baru');
        }

        plugins.set(name, ws);
        console.log(`[Relay] 🎮 Server Minecraft terhubung: ${name}. (IP: ${req.socket.remoteAddress})`);
        
        broadcastToCli({ type: '_relay_info', servers: Array.from(plugins.keys()) });

        ws.on('message', (msg) => {
            if (++messageCount > MAX_MSGS_PER_SEC) return; // Drop spam dari server MC

            try {
                const payload = JSON.parse(msg);
                if (payload && typeof payload === 'object') {
                    broadcastToCli({ server: name, payload });
                }
            } catch(e) {}
        });

        ws.on('close', () => {
            clearInterval(rateLimiter);
            // Hapus dari map HANYA JIKA socket-nya cocok (mencegah bug putus-nyambung cepat)
            if (plugins.get(name) === ws) {
                plugins.delete(name);
                console.log(`[Relay] ❌ Server Minecraft terputus: ${name}`);
                broadcastToCli({ type: '_relay_info', servers: Array.from(plugins.keys()) });
            }
        });
    }
});

// Broadcast helper
function broadcastToCli(data) {
    const str = JSON.stringify(data);
    for (const cli of clis) {
        cli.send(str);
    }
}

// 🛡️ FITUR KEAMANAN 2 (Lanjutan): Ping tiap 30 detik untuk membuang socket mati
const heartbeatInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate(); // Paksa putus tanpa basa basi
        ws.isAlive = false;
        ws.ping(); // Kirim ping, tunggu client balas dengan pong
    });
}, 30000);

wss.on('close', () => clearInterval(heartbeatInterval));

server.listen(PORT, () => {
    console.log(`🚀 Secure Relay Server Berjalan di Port ${PORT}`);
    console.log(`🛡️  Proteksi Aktif: Token Timing-Safe, Rate Limiter, Anti-Zombie & Payload Limiter\n`);
});
