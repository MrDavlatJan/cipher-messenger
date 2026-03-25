const express = require('express');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const http = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const db = new Database('messenger.db');
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

// ─── Database setup ───────────────────────────────────────────────────────────
db.exec(`
  PRAGMA journal_mode=WAL;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    avatar_color TEXT NOT NULL DEFAULT '#6366f1',
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    name TEXT,
    is_group INTEGER DEFAULT 0,
    created_by TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS chat_members (
    chat_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (chat_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id);
`);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static('public'));

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ─── Username plans ───────────────────────────────────────────────────────────
// When adding paid tiers: check user.plan against USERNAME_PLANS[plan]
// e.g. if (username.length < USERNAME_PLANS[user.plan]) → reject
const USERNAME_PLANS = { elite: 2, pro: 3, plus: 4, free: 5 };
const MIN_FREE = USERNAME_PLANS.free; // change this one value to unlock shorter names for free
const MAX_LENGTH = 32;

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password)
    return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (username.length < MIN_FREE || username.length > MAX_LENGTH)
    return res.status(400).json({ error: `Username must be ${MIN_FREE}–${MAX_LENGTH} characters` });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username: only letters, numbers, underscores' });

  const colors = ['#6366f1','#ec4899','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ef4444','#06b6d4'];
  const color = colors[Math.floor(Math.random() * colors.length)];

  try {
    const hash = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    db.prepare(
      'INSERT INTO users (id, email, username, password_hash, avatar_color) VALUES (?, ?, ?, ?, ?)'
    ).run(id, email.toLowerCase().trim(), username.trim(), hash, color);

    const token = jwt.sign({ id, username, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id, username, email: email.toLowerCase(), avatar_color: color } });
  } catch (e) {
    if (e.message?.includes('UNIQUE')) {
      res.status(400).json({ error: 'Email or username already taken' });
    } else {
      console.error(e);
      res.status(500).json({ error: 'Server error' });
    }
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, avatar_color: user.avatar_color } });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, avatar_color FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ─── User routes ───────────────────────────────────────────────────────────────
// Public — no auth needed, used on registration form
app.get('/api/users/check-username', (req, res) => {
  const { username } = req.query;
  if (!username) return res.json({ available: false });
  const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(username.trim());
  res.json({ available: !exists });
});

app.get('/api/users/search', auth, (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 1) return res.json([]);
  const users = db.prepare(
    'SELECT id, username, avatar_color FROM users WHERE username LIKE ? AND id != ? LIMIT 10'
  ).all(`%${q}%`, req.user.id);
  res.json(users);
});

// ─── Chat routes ──────────────────────────────────────────────────────────────
app.get('/api/chats', auth, (req, res) => {
  const chats = db.prepare(`
    SELECT c.*,
      (SELECT content FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
      (SELECT username FROM users u JOIN messages m ON m.sender_id = u.id WHERE m.chat_id = c.id ORDER BY m.created_at DESC LIMIT 1) as last_sender
    FROM chats c
    JOIN chat_members cm ON cm.chat_id = c.id
    WHERE cm.user_id = ?
    ORDER BY COALESCE(last_message_at, c.created_at) DESC
  `).all(req.user.id);

  const result = chats.map(chat => {
    if (!chat.is_group) {
      const other = db.prepare(`
        SELECT u.id, u.username, u.avatar_color FROM users u
        JOIN chat_members cm ON cm.user_id = u.id
        WHERE cm.chat_id = ? AND u.id != ?
      `).get(chat.id, req.user.id);
      return { ...chat, display_name: other?.username || 'Unknown', other_user: other };
    }
    const members = db.prepare(`
      SELECT u.id, u.username FROM users u
      JOIN chat_members cm ON cm.user_id = u.id
      WHERE cm.chat_id = ?
    `).all(chat.id);
    return { ...chat, display_name: chat.name, members };
  });

  res.json(result);
});

app.post('/api/chats/dm', auth, (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });

  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(user_id);
  if (!target) return res.status(404).json({ error: 'User not found' });

  const existing = db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members cm1 ON cm1.chat_id = c.id AND cm1.user_id = ?
    JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id = ?
    WHERE c.is_group = 0
    LIMIT 1
  `).get(req.user.id, user_id);

  if (existing) return res.json({ id: existing.id });

  const id = uuidv4();
  db.prepare('INSERT INTO chats (id, is_group, created_by) VALUES (?, 0, ?)').run(id, req.user.id);
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(id, req.user.id);
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(id, user_id);
  res.json({ id });
});

app.post('/api/chats/group', auth, (req, res) => {
  const { name, member_ids } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Group name required' });

  const id = uuidv4();
  db.prepare('INSERT INTO chats (id, name, is_group, created_by) VALUES (?, ?, 1, ?)').run(id, name.trim(), req.user.id);
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(id, req.user.id);

  for (const uid of (member_ids || [])) {
    try { db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(id, uid); } catch {}
  }
  res.json({ id });
});

app.get('/api/chats/:id/messages', auth, (req, res) => {
  const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not a member' });

  const messages = db.prepare(`
    SELECT m.id, m.chat_id, m.sender_id, m.content, m.created_at,
           u.username, u.avatar_color
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    WHERE m.chat_id = ?
    ORDER BY m.created_at ASC
    LIMIT 200
  `).all(req.params.id);

  res.json(messages);
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
const clients = new Map(); // userId -> Set<ws>

const broadcast = (userIds, payload) => {
  const msg = JSON.stringify(payload);
  for (const uid of userIds) {
    const sockets = clients.get(uid);
    if (sockets) {
      for (const sock of sockets) {
        if (sock.readyState === 1) sock.send(msg);
      }
    }
  }
};

wss.on('connection', (ws) => {
  let userId = null;

  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw);

      if (data.type === 'auth') {
        try {
          const decoded = jwt.verify(data.token, JWT_SECRET);
          userId = decoded.id;
          if (!clients.has(userId)) clients.set(userId, new Set());
          clients.get(userId).add(ws);
          ws.send(JSON.stringify({ type: 'auth_ok' }));
        } catch {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
        }
        return;
      }

      if (!userId) return;

      if (data.type === 'message') {
        const { chat_id, content } = data;
        if (!content?.trim()) return;

        const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chat_id, userId);
        if (!member) return;

        const id = uuidv4();
        const now = Math.floor(Date.now() / 1000);
        db.prepare('INSERT INTO messages (id, chat_id, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?)').run(id, chat_id, userId, content.trim(), now);

        const sender = db.prepare('SELECT username, avatar_color FROM users WHERE id = ?').get(userId);
        const msg = { id, chat_id, sender_id: userId, content: content.trim(), created_at: now, username: sender.username, avatar_color: sender.avatar_color };

        const members = db.prepare('SELECT user_id FROM chat_members WHERE chat_id = ?').all(chat_id);
        broadcast(members.map(m => m.user_id), { type: 'message', message: msg });
      }

      if (data.type === 'typing') {
        const { chat_id, is_typing } = data;
        const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chat_id, userId);
        if (!member) return;
        const sender = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
        const members = db.prepare('SELECT user_id FROM chat_members WHERE chat_id = ?').all(chat_id);
        broadcast(
          members.map(m => m.user_id).filter(id => id !== userId),
          { type: 'typing', chat_id, user_id: userId, username: sender.username, is_typing }
        );
      }
    } catch {}
  });

  ws.on('close', () => {
    if (userId && clients.has(userId)) {
      clients.get(userId).delete(ws);
      if (clients.get(userId).size === 0) clients.delete(userId);
    }
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✓ Messenger running at http://localhost:${PORT}`);
});
