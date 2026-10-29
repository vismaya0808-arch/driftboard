const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 3000;

// ---------- database ----------
const db = new Database(path.join(__dirname, 'driftboard.db'));
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS members (
  project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (project_id, user_id));
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL, description TEXT DEFAULT '',
  status TEXT DEFAULT 'adrift', priority TEXT DEFAULT 'calm',
  assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  creator_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_id INTEGER, text TEXT NOT NULL, read INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

const STATUSES = ['adrift', 'underway', 'docked'];
const PRIORITIES = ['calm', 'choppy', 'storm'];

// ---------- app + sockets ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const sign = (u) => jwt.sign({ id: u.id, name: u.name }, SECRET, { expiresIn: '7d' });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

const auth = (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').slice(7), SECRET);
    next();
  } catch {
    bad(res, 'Please sign in again', 401);
  }
};
const isMember = (pid, uid) =>
  !!db.prepare('SELECT 1 FROM members WHERE project_id=? AND user_id=?').get(pid, uid);

function notify(userId, projectId, text) {
  const info = db.prepare('INSERT INTO notifications (user_id, project_id, text) VALUES (?,?,?)')
    .run(userId, projectId, text);
  io.to('user:' + userId).emit('notify', db.prepare('SELECT * FROM notifications WHERE id=?').get(info.lastInsertRowid));
}
const changed = (projectId, what) => io.to('project:' + projectId).emit('board:changed', { projectId, what });

// ---------- auth ----------
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password || password.length < 6)
    return bad(res, 'Name, email and a password of 6+ characters are required');
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email.toLowerCase()))
    return bad(res, 'That email is already registered', 409);
  const info = db.prepare('INSERT INTO users (name,email,hash) VALUES (?,?,?)')
    .run(name.trim(), email.toLowerCase(), bcrypt.hashSync(password, 10));
  const user = { id: info.lastInsertRowid, name: name.trim() };
  res.json({ token: sign(user), user });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(password || '', u.hash)) return bad(res, 'Wrong email or password', 401);
  res.json({ token: sign(u), user: { id: u.id, name: u.name } });
});

// ---------- projects ----------
app.get('/api/projects', auth, (req, res) => {
  res.json(db.prepare(`SELECT p.id, p.name FROM projects p
    JOIN members m ON m.project_id=p.id WHERE m.user_id=? ORDER BY p.id DESC`).all(req.user.id));
});

app.post('/api/projects', auth, (req, res) => {
  const name = (req.body.name || '').trim();
  if (!name) return bad(res, 'Give the project a name');
  const info = db.prepare('INSERT INTO projects (name, owner_id) VALUES (?,?)').run(name, req.user.id);
  db.prepare('INSERT INTO members VALUES (?,?)').run(info.lastInsertRowid, req.user.id);
  res.json({ id: info.lastInsertRowid, name });
});

app.get('/api/projects/:id', auth, (req, res) => {
  const pid = +req.params.id;
  if (!isMember(pid, req.user.id)) return bad(res, 'Not a member of this project', 403);
  res.json({
    project: db.prepare('SELECT * FROM projects WHERE id=?').get(pid),
    members: db.prepare(`SELECT u.id, u.name, u.email FROM users u
      JOIN members m ON m.user_id=u.id WHERE m.project_id=?`).all(pid),
    tasks: db.prepare(`SELECT t.*, u.name AS assignee_name,
      (SELECT COUNT(*) FROM comments c WHERE c.task_id=t.id) AS comment_count
      FROM tasks t LEFT JOIN users u ON u.id=t.assignee_id WHERE t.project_id=? ORDER BY t.id`).all(pid),
  });
});

app.post('/api/projects/:id/members', auth, (req, res) => {
  const pid = +req.params.id;
  if (!isMember(pid, req.user.id)) return bad(res, 'Not a member of this project', 403);
  const u = db.prepare('SELECT id, name FROM users WHERE email=?').get((req.body.email || '').toLowerCase());
  if (!u) return bad(res, 'No user with that email. Ask them to register first', 404);
  db.prepare('INSERT OR IGNORE INTO members VALUES (?,?)').run(pid, u.id);
  const p = db.prepare('SELECT name FROM projects WHERE id=?').get(pid);
  notify(u.id, pid, `${req.user.name} added you to “${p.name}”`);
  changed(pid, 'members');
  res.json({ ok: true });
});

// ---------- tasks ----------
app.post('/api/projects/:id/tasks', auth, (req, res) => {
  const pid = +req.params.id;
  if (!isMember(pid, req.user.id)) return bad(res, 'Not a member of this project', 403);
  const title = (req.body.title || '').trim();
  if (!title) return bad(res, 'A task needs a title');
  const info = db.prepare('INSERT INTO tasks (project_id,title,creator_id) VALUES (?,?,?)')
    .run(pid, title, req.user.id);
  changed(pid, 'task');
  res.json({ id: info.lastInsertRowid });
});

function loadTask(req, res, next) {
  const t = db.prepare('SELECT * FROM tasks WHERE id=?').get(+req.params.id);
  if (!t) return bad(res, 'Task not found', 404);
  if (!isMember(t.project_id, req.user.id)) return bad(res, 'Not a member of this project', 403);
  req.task = t;
  next();
}

app.patch('/api/tasks/:id', auth, loadTask, (req, res) => {
  const t = req.task, b = req.body;
  const next = {
    title: (b.title ?? t.title).trim() || t.title,
    description: b.description ?? t.description,
    status: STATUSES.includes(b.status) ? b.status : t.status,
    priority: PRIORITIES.includes(b.priority) ? b.priority : t.priority,
    assignee_id: 'assignee_id' in b ? (b.assignee_id || null) : t.assignee_id,
  };
  if (next.assignee_id && !isMember(t.project_id, next.assignee_id))
    return bad(res, 'Assignee must be a project member');
  db.prepare(`UPDATE tasks SET title=?, description=?, status=?, priority=?, assignee_id=? WHERE id=?`)
    .run(next.title, next.description, next.status, next.priority, next.assignee_id, t.id);
  if (next.assignee_id && next.assignee_id !== t.assignee_id && next.assignee_id !== req.user.id)
    notify(next.assignee_id, t.project_id, `${req.user.name} assigned you “${next.title}”`);
  if (next.status !== t.status && t.assignee_id && t.assignee_id !== req.user.id)
    notify(t.assignee_id, t.project_id, `${req.user.name} moved “${next.title}” to ${next.status}`);
  changed(t.project_id, 'task');
  res.json({ ok: true });
});

app.delete('/api/tasks/:id', auth, loadTask, (req, res) => {
  db.prepare('DELETE FROM tasks WHERE id=?').run(req.task.id);
  changed(req.task.project_id, 'task');
  res.json({ ok: true });
});

// ---------- comments ----------
app.get('/api/tasks/:id/comments', auth, loadTask, (req, res) => {
  res.json(db.prepare(`SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.user_id
    WHERE c.task_id=? ORDER BY c.id`).all(req.task.id));
});

app.post('/api/tasks/:id/comments', auth, loadTask, (req, res) => {
  const body = (req.body.body || '').trim();
  if (!body) return bad(res, 'Write something first');
  const t = req.task;
  db.prepare('INSERT INTO comments (task_id,user_id,body) VALUES (?,?,?)').run(t.id, req.user.id, body);
  new Set([t.assignee_id, t.creator_id]).forEach((uid) => {
    if (uid && uid !== req.user.id) notify(uid, t.project_id, `${req.user.name} commented on “${t.title}”`);
  });
  changed(t.project_id, 'comment');
  res.json({ ok: true });
});

// ---------- notifications ----------
app.get('/api/notifications', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30').all(req.user.id));
});
app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(req.user.id);
  res.json({ ok: true });
});

// ---------- real-time ----------
const presence = {}; // projectId -> { socketId: name }
io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, SECRET);
    next();
  } catch {
    next(new Error('unauthorized'));
  }
});
io.on('connection', (socket) => {
  socket.join('user:' + socket.user.id);
  socket.on('join', (pid) => {
    if (!isMember(pid, socket.user.id)) return;
    socket.join('project:' + pid);
    socket.pid = pid;
    (presence[pid] ||= {})[socket.id] = socket.user.name;
    io.to('project:' + pid).emit('presence', [...new Set(Object.values(presence[pid]))]);
  });
  socket.on('leave', (pid) => {
    socket.leave('project:' + pid);
    if (presence[pid]) delete presence[pid][socket.id];
    io.to('project:' + pid).emit('presence', [...new Set(Object.values(presence[pid] || {}))]);
  });
  socket.on('disconnect', () => {
    const pid = socket.pid;
    if (pid && presence[pid]) {
      delete presence[pid][socket.id];
      io.to('project:' + pid).emit('presence', [...new Set(Object.values(presence[pid]))]);
    }
  });
});

server.listen(PORT, () => console.log(`Driftboard running at http://localhost:${PORT}`));
