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

// ─── Profanity ────────────────────────────────────────────────────────────────
const BANNED_WORDS = [
  'fuck','shit','bitch','cunt','dick','cock','pussy','nigger','nigga','fag','faggot',
  'whore','slut','bastard','retard','asshole','motherfucker',
  'хуй','пизда','блядь','залупа','ёбаный','пидор','мудак','сука','шлюха','мразь','ублюдок','долбоёб','долбоеб',
  'pizdec','pizda','blyad','blyat','hui','huy','mudak','pidor','shlukha','mraz','eban','ebat','nahui','blyadi','pidar','pidoras'
];
const containsBannedWord = str => BANNED_WORDS.some(w => str.toLowerCase().replace(/[_0-9]/g,'').includes(w));
const isValidEmail = e => /^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/.test(e);
const randInvite = () => '+cgr' + Array.from({length:7},()=>'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random()*36)]).join('');

// ─── DB Setup ─────────────────────────────────────────────────────────────────
db.exec(`
  PRAGMA journal_mode=WAL;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE, first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT, password_hash TEXT NOT NULL,
    avatar_color TEXT NOT NULL DEFAULT '#6366f1',
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY, name TEXT, is_group INTEGER DEFAULT 0,
    created_by TEXT, invite_code TEXT UNIQUE,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS chat_members (
    chat_id TEXT NOT NULL, user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (chat_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, chat_id TEXT NOT NULL,
    sender_id TEXT NOT NULL, content TEXT NOT NULL,
    original_content TEXT,
    status TEXT NOT NULL DEFAULT 'sent',
    is_deleted INTEGER DEFAULT 0,
    is_edited INTEGER DEFAULT 0,
    forwarded_from TEXT,
    reply_to_id TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    edited_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS read_receipts (
    chat_id TEXT NOT NULL, user_id TEXT NOT NULL,
    last_read_msg_id TEXT NOT NULL,
    PRIMARY KEY (chat_id, user_id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id);
  CREATE INDEX IF NOT EXISTS idx_invite ON chats(invite_code);
`);

// Migrations
const migrations = [
  `ALTER TABLE users ADD COLUMN username TEXT UNIQUE`,
  `ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN last_name TEXT`,
  `ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT 'sent'`,
  `ALTER TABLE messages ADD COLUMN original_content TEXT`,
  `ALTER TABLE messages ADD COLUMN is_deleted INTEGER DEFAULT 0`,
  `ALTER TABLE messages ADD COLUMN is_edited INTEGER DEFAULT 0`,
  `ALTER TABLE messages ADD COLUMN forwarded_from TEXT`,
  `ALTER TABLE messages ADD COLUMN reply_to_id TEXT`,
  `ALTER TABLE messages ADD COLUMN edited_at INTEGER`,
  `ALTER TABLE chats ADD COLUMN invite_code TEXT UNIQUE`,
  `ALTER TABLE chat_members ADD COLUMN role TEXT NOT NULL DEFAULT 'member'`,
  `ALTER TABLE chat_members ADD COLUMN can_rename INTEGER DEFAULT 0`,
  `ALTER TABLE chat_members ADD COLUMN can_add INTEGER DEFAULT 0`,
  `ALTER TABLE chat_members ADD COLUMN can_kick INTEGER DEFAULT 0`,
];
for (const m of migrations) { try { db.exec(m); } catch {} }

// Ensure existing groups have invite codes
const groupsWithoutCode = db.prepare(`SELECT id FROM chats WHERE is_group=1 AND (invite_code IS NULL OR invite_code='')`).all();
for (const g of groupsWithoutCode) {
  let code; do { code = randInvite(); } while (db.prepare('SELECT 1 FROM chats WHERE invite_code=?').get(code));
  db.prepare('UPDATE chats SET invite_code=? WHERE id=?').run(code, g.id);
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static('public'));

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

const MIN_FREE = 5, MAX_LENGTH = 32;

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { email, username, password, first_name, last_name } = req.body;
  if (!email || !password || !first_name)
    return res.status(400).json({ error: 'Email, password and first name are required' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email address' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (first_name.trim().length < 1) return res.status(400).json({ error: 'First name required' });

  // Username is optional but validated if provided
  if (username) {
    if (username.length < MIN_FREE || username.length > MAX_LENGTH)
      return res.status(400).json({ error: `Username must be ${MIN_FREE}–${MAX_LENGTH} characters` });
    if (!/^[a-zA-Z0-9_]+$/.test(username))
      return res.status(400).json({ error: 'Username: only letters, numbers, underscores' });
    if (containsBannedWord(username))
      return res.status(400).json({ error: 'This username is not allowed' });
  }

  const colors = ['#6366f1','#ec4899','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ef4444','#06b6d4'];
  const color = colors[Math.floor(Math.random() * colors.length)];
  try {
    const hash = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    db.prepare('INSERT INTO users (id,email,username,first_name,last_name,password_hash,avatar_color) VALUES (?,?,?,?,?,?,?)')
      .run(id, email.toLowerCase().trim(), username?.trim()||null, first_name.trim(), last_name?.trim()||null, hash, color);
    const token = jwt.sign({ id, username: username||null, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id, username: username||null, email: email.toLowerCase(), first_name: first_name.trim(), last_name: last_name?.trim()||null, avatar_color: color } });
  } catch (e) {
    if (e.message?.includes('UNIQUE')) res.status(400).json({ error: 'Email already taken' });
    else { console.error(e); res.status(500).json({ error: 'Server error' }); }
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email||!password) return res.status(400).json({ error: 'All fields required' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email address' });
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase().trim());
  if (!user||!bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, first_name: user.first_name, last_name: user.last_name, avatar_color: user.avatar_color } });
});

app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT id,username,email,first_name,last_name,avatar_color FROM users WHERE id=?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json(u);
});

app.patch('/api/me', auth, (req, res) => {
  const { username, first_name, last_name } = req.body;
  const updates = {};
  if (username !== undefined) {
    if (username === null || username === '') {
      updates.username = null; // allow clearing username
    } else {
      if (username.length < MIN_FREE || username.length > MAX_LENGTH)
        return res.status(400).json({ error: `Username must be ${MIN_FREE}–${MAX_LENGTH} characters` });
      if (!/^[a-zA-Z0-9_]+$/.test(username))
        return res.status(400).json({ error: 'Username: only letters, numbers, underscores' });
      if (containsBannedWord(username))
        return res.status(400).json({ error: 'This username is not allowed' });
      // Check uniqueness — but only against OTHER users
      const existing = db.prepare('SELECT id FROM users WHERE username=? AND id!=?').get(username.trim(), req.user.id);
      if (existing) return res.status(400).json({ error: 'Username already taken' });
      updates.username = username.trim();
    }
  }
  if (first_name !== undefined) {
    if (first_name.trim().length < 1) return res.status(400).json({ error: 'First name required' });
    updates.first_name = first_name.trim();
  }
  if (last_name !== undefined) updates.last_name = last_name?.trim()||null;
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Nothing to update' });

  try {
    const fields = Object.keys(updates).map(k=>`${k}=?`).join(', ');
    db.prepare(`UPDATE users SET ${fields} WHERE id=?`).run(...Object.values(updates), req.user.id);
    const updated = db.prepare('SELECT id,username,email,first_name,last_name,avatar_color FROM users WHERE id=?').get(req.user.id);
    res.json(updated);
  } catch (e) {
    if (e.message?.includes('UNIQUE')) res.status(400).json({ error: 'Username already taken' });
    else { console.error(e); res.status(500).json({ error: 'Server error' }); }
  }
});

app.get('/api/me/username-check', auth, (req, res) => {
  const u = db.prepare('SELECT username FROM users WHERE id=?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ banned: u.username ? containsBannedWord(u.username) : false });
});

// ─── Users ────────────────────────────────────────────────────────────────────
app.get('/api/users/check-username', (req, res) => {
  const { username, exclude_id } = req.query;
  if (!username) return res.json({ available: false });
  const exists = db.prepare('SELECT 1 FROM users WHERE username=?' + (exclude_id ? ' AND id!=?' : '')).get(...[username.trim(), exclude_id].filter(Boolean));
  res.json({ available: !exists, banned: containsBannedWord(username) });
});

// Search only users who HAVE a username, min 3 chars match
app.get('/api/users/search', auth, (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 3) return res.json([]);
  const users = db.prepare(
    `SELECT id,username,first_name,last_name,avatar_color FROM users
     WHERE username IS NOT NULL AND username!='' AND username LIKE ? AND id!=? LIMIT 10`
  ).all(`%${q}%`, req.user.id);
  res.json(users);
});

// ─── Chats ────────────────────────────────────────────────────────────────────
app.get('/api/chats', auth, (req, res) => {
  const chats = db.prepare(`
    SELECT c.*,
      (SELECT content FROM messages WHERE chat_id=c.id AND is_deleted=0 ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
      (SELECT u.username FROM users u JOIN messages m ON m.sender_id=u.id WHERE m.chat_id=c.id ORDER BY m.created_at DESC LIMIT 1) as last_sender,
      cm.role as my_role
    FROM chats c JOIN chat_members cm ON cm.chat_id=c.id
    WHERE cm.user_id=?
    ORDER BY COALESCE(last_message_at,c.created_at) DESC
  `).all(req.user.id);

  const result = chats.map(chat => {
    if (!chat.is_group) {
      const other = db.prepare(`SELECT u.id,u.username,u.first_name,u.last_name,u.avatar_color FROM users u JOIN chat_members cm ON cm.user_id=u.id WHERE cm.chat_id=? AND u.id!=?`).get(chat.id, req.user.id);
      const dn = other ? (other.first_name+(other.last_name?' '+other.last_name:'')) : 'Unknown';
      return { ...chat, display_name: dn, other_user: other };
    }
    const members = db.prepare(`SELECT u.id,u.username,u.first_name,u.last_name,u.avatar_color,cm.role,cm.can_rename,cm.can_add,cm.can_kick FROM users u JOIN chat_members cm ON cm.user_id=u.id WHERE cm.chat_id=?`).all(chat.id);
    return { ...chat, display_name: chat.name, members };
  });
  res.json(result);
});

app.post('/api/chats/dm', auth, (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  if (user_id === req.user.id) return res.status(400).json({ error: "Can't DM yourself" });
  const target = db.prepare('SELECT id FROM users WHERE id=?').get(user_id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const existing = db.prepare(`SELECT c.id FROM chats c JOIN chat_members cm1 ON cm1.chat_id=c.id AND cm1.user_id=? JOIN chat_members cm2 ON cm2.chat_id=c.id AND cm2.user_id=? WHERE c.is_group=0 LIMIT 1`).get(req.user.id, user_id);
  if (existing) return res.json({ id: existing.id });
  const id = uuidv4();
  db.prepare('INSERT INTO chats (id,is_group,created_by) VALUES (?,0,?)').run(id, req.user.id);
  db.prepare('INSERT INTO chat_members (chat_id,user_id,role) VALUES (?,?,?)').run(id, req.user.id, 'member');
  db.prepare('INSERT INTO chat_members (chat_id,user_id,role) VALUES (?,?,?)').run(id, user_id, 'member');
  res.json({ id });
});

app.post('/api/chats/group', auth, (req, res) => {
  const { name, member_ids } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Group name required' });
  const id = uuidv4();
  let code; do { code = randInvite(); } while (db.prepare('SELECT 1 FROM chats WHERE invite_code=?').get(code));
  db.prepare('INSERT INTO chats (id,name,is_group,created_by,invite_code) VALUES (?,?,1,?,?)').run(id, name.trim(), req.user.id, code);
  db.prepare('INSERT INTO chat_members (chat_id,user_id,role) VALUES (?,?,?)').run(id, req.user.id, 'admin');
  for (const uid of (member_ids||[])) {
    try { db.prepare('INSERT INTO chat_members (chat_id,user_id,role) VALUES (?,?,?)').run(id, uid, 'member'); } catch {}
  }
  res.json({ id, invite_code: code });
});

// ─── Group admin operations ───────────────────────────────────────────────────
// Rename group — admin OR member with can_rename
app.patch('/api/chats/:id', auth, (req, res) => {
  const { name } = req.body;
  const chat = db.prepare('SELECT * FROM chats WHERE id=? AND is_group=1').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Group not found' });
  const member = db.prepare('SELECT role,can_rename FROM chat_members WHERE chat_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!member || (member.role !== 'admin' && !member.can_rename)) return res.status(403).json({ error: 'No permission to rename' });
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  db.prepare('UPDATE chats SET name=? WHERE id=?').run(name.trim(), req.params.id);
  res.json({ ok: true, name: name.trim() });
});

// Regenerate invite code
app.post('/api/chats/:id/regen-invite', auth, (req, res) => {
  const member = db.prepare('SELECT role FROM chat_members WHERE chat_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!member || member.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  let code; do { code = randInvite(); } while (db.prepare('SELECT 1 FROM chats WHERE invite_code=?').get(code));
  db.prepare('UPDATE chats SET invite_code=? WHERE id=?').run(code, req.params.id);
  res.json({ invite_code: code });
});

// Add member — admin OR member with can_add
app.post('/api/chats/:id/members', auth, (req, res) => {
  const { user_id, role } = req.body;
  const member = db.prepare('SELECT role,can_add FROM chat_members WHERE chat_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!member || (member.role !== 'admin' && !member.can_add)) return res.status(403).json({ error: 'No permission to add members' });
  try {
    db.prepare('INSERT INTO chat_members (chat_id,user_id,role) VALUES (?,?,?)').run(req.params.id, user_id, role||'member');
    const u = db.prepare('SELECT id,username,first_name,last_name,avatar_color FROM users WHERE id=?').get(user_id);
    res.json(u);
  } catch { res.status(400).json({ error: 'Already a member' }); }
});

// Remove member — admin OR member with can_kick (can't kick admins)
app.delete('/api/chats/:id/members/:userId', auth, (req, res) => {
  const { id, userId } = req.params;
  if (userId !== req.user.id) {
    const myRole = db.prepare('SELECT role,can_kick FROM chat_members WHERE chat_id=? AND user_id=?').get(id, req.user.id);
    if (!myRole || (myRole.role !== 'admin' && !myRole.can_kick)) return res.status(403).json({ error: 'No permission to remove members' });
    // Can't kick admins unless you're admin
    const targetRole = db.prepare('SELECT role FROM chat_members WHERE chat_id=? AND user_id=?').get(id, userId);
    if (targetRole?.role === 'admin' && myRole.role !== 'admin') return res.status(403).json({ error: "Can't remove an admin" });
  }
  db.prepare('DELETE FROM chat_members WHERE chat_id=? AND user_id=?').run(id, userId);
  res.json({ ok: true });
});

// Change member role + privileges (admin only)
app.patch('/api/chats/:id/members/:userId', auth, (req, res) => {
  const { role, can_rename, can_add, can_kick } = req.body;
  const myRole = db.prepare('SELECT role FROM chat_members WHERE chat_id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!myRole || myRole.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (role !== undefined) {
    if (!['admin','member'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    db.prepare('UPDATE chat_members SET role=? WHERE chat_id=? AND user_id=?').run(role, req.params.id, req.params.userId);
    // admins get all privileges automatically; demoting clears them
    if (role === 'admin') db.prepare('UPDATE chat_members SET can_rename=1,can_add=1,can_kick=1 WHERE chat_id=? AND user_id=?').run(req.params.id, req.params.userId);
    if (role === 'member') db.prepare('UPDATE chat_members SET can_rename=0,can_add=0,can_kick=0 WHERE chat_id=? AND user_id=?').run(req.params.id, req.params.userId);
  }
  // Granular privileges — admin can grant individually
  const updates = [];
  if (can_rename !== undefined) updates.push(['can_rename', can_rename ? 1 : 0]);
  if (can_add    !== undefined) updates.push(['can_add',    can_add    ? 1 : 0]);
  if (can_kick   !== undefined) updates.push(['can_kick',   can_kick   ? 1 : 0]);
  for (const [col, val] of updates) {
    db.prepare(`UPDATE chat_members SET ${col}=? WHERE chat_id=? AND user_id=?`).run(val, req.params.id, req.params.userId);
  }
  const updated = db.prepare('SELECT role,can_rename,can_add,can_kick FROM chat_members WHERE chat_id=? AND user_id=?').get(req.params.id, req.params.userId);
  res.json({ ok: true, ...updated });
});

// ─── Group invite preview ─────────────────────────────────────────────────────
app.get('/api/invite/:code', auth, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE invite_code=?').get(req.params.code);
  if (!chat) return res.status(404).json({ error: 'Invalid invite link' });
  const members = db.prepare(`SELECT u.id,u.first_name,u.last_name,u.username,u.avatar_color,cm.role FROM users u JOIN chat_members cm ON cm.user_id=u.id WHERE cm.chat_id=?`).all(chat.id);
  const preview = db.prepare(`SELECT m.id,m.content,m.created_at,m.is_deleted,m.is_edited,m.forwarded_from,u.first_name,u.last_name,u.username,u.avatar_color FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? ORDER BY m.created_at DESC LIMIT 5`).all(chat.id).reverse();
  const alreadyMember = !!db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chat.id, req.user.id);
  res.json({ chat, members, preview, alreadyMember });
});

// Join via invite
app.post('/api/invite/:code/join', auth, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE invite_code=?').get(req.params.code);
  if (!chat) return res.status(404).json({ error: 'Invalid invite link' });
  try {
    db.prepare('INSERT INTO chat_members (chat_id,user_id,role) VALUES (?,?,?)').run(chat.id, req.user.id, 'member');
  } catch {} // already member
  res.json({ id: chat.id });
});

// ─── Messages ─────────────────────────────────────────────────────────────────
app.get('/api/chats/:id/messages', auth, (req, res) => {
  if (!db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(req.params.id, req.user.id))
    return res.status(403).json({ error: 'Not a member' });
  const messages = db.prepare(`
    SELECT m.id,m.chat_id,m.sender_id,m.content,m.original_content,m.status,m.is_deleted,m.is_edited,m.forwarded_from,m.reply_to_id,m.created_at,m.edited_at,
           u.username,u.first_name,u.last_name,u.avatar_color
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE m.chat_id=? ORDER BY m.created_at ASC LIMIT 300
  `).all(req.params.id);
  res.json(messages);
});

// Edit message
app.patch('/api/messages/:id', auth, (req, res) => {
  const { content } = req.body;
  const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Not your message' });
  if (msg.is_deleted) return res.status(400).json({ error: 'Message deleted' });
  if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
  const originalContent = msg.is_edited ? msg.original_content : msg.content;
  db.prepare('UPDATE messages SET content=?,original_content=?,is_edited=1,edited_at=unixepoch() WHERE id=?').run(content.trim(), originalContent, req.params.id);
  const updated = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.id);
  res.json(updated);
});

// Delete message
app.delete('/api/messages/:id', auth, (req, res) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(req.params.id);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Not your message' });
  const originalContent = msg.is_edited ? msg.original_content : msg.content;
  db.prepare('UPDATE messages SET is_deleted=1,original_content=?,content=?,edited_at=unixepoch() WHERE id=?').run(originalContent, msg.content, msg.id);
  res.json({ ok: true });
});

// Mark read
app.post('/api/chats/:id/read', auth, (req, res) => {
  const chatId = req.params.id;
  if (!db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chatId, req.user.id))
    return res.status(403).json({ error: 'Not a member' });
  const lastMsg = db.prepare('SELECT id,sender_id FROM messages WHERE chat_id=? ORDER BY created_at DESC LIMIT 1').get(chatId);
  if (!lastMsg) return res.json({ ok: true });
  db.prepare('INSERT OR REPLACE INTO read_receipts (chat_id,user_id,last_read_msg_id) VALUES (?,?,?)').run(chatId, req.user.id, lastMsg.id);
  db.prepare(`UPDATE messages SET status='read' WHERE chat_id=? AND sender_id!=? AND status!='read'`).run(chatId, req.user.id);
  res.json({ ok: true });
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
const clients = new Map();
const broadcast = (uids, payload) => {
  const s = JSON.stringify(payload);
  for (const uid of uids) { const ss = clients.get(uid); if (ss) for (const sock of ss) if (sock.readyState===1) sock.send(s); }
};

wss.on('connection', ws => {
  let userId = null;

  ws.on('message', raw => {
    try {
      const data = JSON.parse(raw);

      if (data.type === 'auth') {
        try {
          const dec = jwt.verify(data.token, JWT_SECRET);
          if (userId && clients.has(userId)) { clients.get(userId).delete(ws); if (!clients.get(userId).size) clients.delete(userId); }
          userId = dec.id;
          if (!clients.has(userId)) clients.set(userId, new Set());
          clients.get(userId).add(ws);
          ws.send(JSON.stringify({ type: 'auth_ok' }));
          // Mark pending sent→delivered
          const pending = db.prepare(`SELECT m.id,m.chat_id,m.sender_id FROM messages m JOIN chat_members cm ON cm.chat_id=m.chat_id AND cm.user_id=? WHERE m.sender_id!=? AND m.status='sent'`).all(userId, userId);
          for (const m of pending) {
            db.prepare(`UPDATE messages SET status='delivered' WHERE id=?`).run(m.id);
            broadcast([m.sender_id], { type: 'status_update', message_id: m.id, chat_id: m.chat_id, status: 'delivered' });
          }
        } catch { ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' })); }
        return;
      }

      if (!userId) return;

      if (data.type === 'message') {
        const { chat_id, content, reply_to_id, forwarded_from } = data;
        if (!content?.trim()) return;
        if (!db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chat_id, userId)) return;

        const id = uuidv4();
        const now = Math.floor(Date.now() / 1000);
        const members = db.prepare('SELECT user_id FROM chat_members WHERE chat_id=?').all(chat_id);
        const others = members.map(m=>m.user_id).filter(u=>u!==userId);
        const anyOnline = others.some(u=>clients.has(u)&&clients.get(u).size>0);
        const initialStatus = anyOnline ? 'delivered' : 'sent';

        db.prepare('INSERT INTO messages (id,chat_id,sender_id,content,status,reply_to_id,forwarded_from,created_at) VALUES (?,?,?,?,?,?,?,?)')
          .run(id, chat_id, userId, content.trim(), initialStatus, reply_to_id||null, forwarded_from||null, now);

        const sender = db.prepare('SELECT username,first_name,last_name,avatar_color FROM users WHERE id=?').get(userId);
        const msg = { id, chat_id, sender_id: userId, content: content.trim(), status: initialStatus, is_deleted: 0, is_edited: 0, reply_to_id: reply_to_id||null, forwarded_from: forwarded_from||null, created_at: now, ...sender };
        broadcast(members.map(m=>m.user_id), { type: 'message', message: msg });
      }

      if (data.type === 'read') {
        const { chat_id } = data;
        if (!db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chat_id, userId)) return;
        const msgs = db.prepare(`SELECT id,sender_id FROM messages WHERE chat_id=? AND sender_id!=? AND status!='read'`).all(chat_id, userId);
        for (const m of msgs) {
          db.prepare(`UPDATE messages SET status='read' WHERE id=?`).run(m.id);
          broadcast([m.sender_id], { type: 'status_update', message_id: m.id, chat_id, status: 'read' });
        }
      }

      if (data.type === 'message_edit') {
        const { message_id, content } = data;
        const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(message_id);
        if (!msg || msg.sender_id !== userId || msg.is_deleted) return;
        const orig = msg.is_edited ? msg.original_content : msg.content;
        const now = Math.floor(Date.now() / 1000);
        db.prepare('UPDATE messages SET content=?,original_content=?,is_edited=1,edited_at=? WHERE id=?').run(content.trim(), orig, now, message_id);
        const members = db.prepare('SELECT user_id FROM chat_members WHERE chat_id=?').all(msg.chat_id);
        broadcast(members.map(m=>m.user_id), { type: 'message_updated', message_id, chat_id: msg.chat_id, content: content.trim(), original_content: orig, is_edited: 1, edited_at: now });
      }

      if (data.type === 'message_delete') {
        const { message_id } = data;
        const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(message_id);
        if (!msg || msg.sender_id !== userId) return;
        const orig = msg.is_edited ? msg.original_content : msg.content;
        const now = Math.floor(Date.now() / 1000);
        db.prepare('UPDATE messages SET is_deleted=1,original_content=?,edited_at=? WHERE id=?').run(orig, now, message_id);
        const members = db.prepare('SELECT user_id FROM chat_members WHERE chat_id=?').all(msg.chat_id);
        broadcast(members.map(m=>m.user_id), { type: 'message_updated', message_id, chat_id: msg.chat_id, content: msg.content, original_content: orig, is_deleted: 1, edited_at: now });
      }

      if (data.type === 'typing') {
        const { chat_id, is_typing } = data;
        if (!db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chat_id, userId)) return;
        const sender = db.prepare('SELECT first_name,username FROM users WHERE id=?').get(userId);
        const members = db.prepare('SELECT user_id FROM chat_members WHERE chat_id=?').all(chat_id);
        broadcast(members.map(m=>m.user_id).filter(u=>u!==userId), { type: 'typing', chat_id, user_id: userId, username: sender.first_name||sender.username, is_typing });
      }
    } catch (e) { console.error('WS error', e); }
  });

  ws.on('close', () => {
    if (userId && clients.has(userId)) { clients.get(userId).delete(ws); if (!clients.get(userId).size) clients.delete(userId); }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`✓ Messenger at http://localhost:${PORT}`));
