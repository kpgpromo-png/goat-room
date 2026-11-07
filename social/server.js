const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3079);
const PREFIX = '/social';
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET is missing or too short');
}

const db = new Database(process.env.DB_FILE || path.join(__dirname, 'social.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(\`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 login TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 name TEXT NOT NULL,
 age INTEGER NOT NULL,
 avatar TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_posts_user_id_id ON posts(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_comments_post_id_id ON comments(post_id, id);
CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver_id ON messages(sender_id, receiver_id, id);
CREATE INDEX IF NOT EXISTS idx_messages_receiver_sender_id ON messages(receiver_id, sender_id, id);
\`);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.json({ limit: '2mb', strict: true }));
app.use(session({
  name: 'social.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));
app.use(PREFIX, express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: '5m'
}));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много попыток. Подожди 15 минут и попробуй снова.' }
});
const writeLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком часто. Подожди немного.' }
});
const clean = value => String(value == null ? '' : value).trim();
const publicUser = user => user ? ({
  id: user.id,
  login: user.login,
  name: user.name,
  age: user.age,
  avatar: user.avatar || ''
}) : null;
const userById = id => db.prepare(
  'SELECT id, login, name, age, avatar FROM users WHERE id = ?'
).get(id);
const needAuth = (req, res, next) => {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: 'Сессия закончилась. Войди в аккаунт ещё раз.' });
};
const regenerateSession = (req, userId) => new Promise((resolve, reject) => {
  req.session.regenerate(error => {
    if (error) return reject(error);
    req.session.userId = userId;
    req.session.save(saveError => saveError ? reject(saveError) : resolve());
  });
});
const asyncRoute = handler => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(next);

app.get(PREFIX + '/api/health', (req, res) => res.json({ ok: true }));

app.post(PREFIX + '/api/register', authLimit, asyncRoute(async (req, res) => {
  const login = clean(req.body && req.body.login).toLowerCase();
  const password = String((req.body && req.body.password) || '');
  const name = clean(req.body && req.body.name);
  const age = Number(req.body && req.body.age);

  if (!/^[a-z0-9_]{3,24}$/.test(login)) {
    return res.status(400).json({ error: 'Логин: от 3 до 24 символов — латиница, цифры и нижнее подчёркивание.' });
  }
  if (password.length < 8 || password.length > 100) {
    return res.status(400).json({ error: 'Пароль должен содержать от 8 до 100 символов.' });
  }
  if (!name || name.length > 40 || !Number.isInteger(age) || age < 13 || age > 120) {
    return res.status(400).json({ error: 'Укажи имя (до 40 символов) и возраст от 13 до 120 лет.' });
  }

  const hash = await bcrypt.hash(password, 12);
  try {
    const info = db.prepare(
      'INSERT INTO users(login, password_hash, name, age) VALUES(?, ?, ?, ?)'
    ).run(login, hash, name, age);
    await regenerateSession(req, Number(info.lastInsertRowid));
    return res.status(201).json({ user: publicUser(userById(req.session.userId)) });
  } catch (error) {
    if (error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Этот логин уже занят. Придумай другой.' });
    }
    throw error;
  }
}));

app.post(PREFIX + '/api/login', authLimit, asyncRoute(async (req, res) => {
  const login = clean(req.body && req.body.login).toLowerCase();
  const password = String((req.body && req.body.password) || '');
  const user = db.prepare('SELECT * FROM users WHERE login = ? COLLATE NOCASE').get(login);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Неверный логин или пароль.' });
  }
  await regenerateSession(req, user.id);
  return res.json({ user: publicUser(user) });
}));

app.post(PREFIX + '/api/logout', (req, res, next) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie('social.sid', { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true' });
    res.json({ ok: true });
  });
});

app.get(PREFIX + '/api/me', (req, res) => {
  res.json({ user: req.session && req.session.userId ? publicUser(userById(req.session.userId)) : null });
});

app.get(PREFIX + '/api/users', needAuth, (req, res) => {
  const q = clean(req.query.q).slice(0, 40).replace(/[\\%_]/g, '\\$&');
  const users = db.prepare(
    "SELECT id, login, name, age, avatar FROM users WHERE login LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\' ORDER BY name COLLATE NOCASE LIMIT 30"
  ).all('%' + q + '%', '%' + q + '%');
  res.json({ users: users.map(publicUser) });
});

app.get(PREFIX + '/api/users/:id', needAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Некорректный ID.' });
  const user = userById(id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден.' });
  const posts = db.prepare(
    'SELECT p.*, u.name, u.login, u.avatar FROM posts p JOIN users u ON u.id = p.user_id WHERE p.user_id = ? ORDER BY p.id DESC LIMIT 50'
  ).all(id);
  res.json({ user: publicUser(user), posts });
});

app.put(PREFIX + '/api/profile', needAuth, writeLimit, (req, res) => {
  const name = clean(req.body && req.body.name);
  const age = Number(req.body && req.body.age);
  const avatar = String((req.body && req.body.avatar) || '');
  if (!name || name.length > 40 || !Number.isInteger(age) || age < 13 || age > 120) {
    return res.status(400).json({ error: 'Проверь имя и возраст от 13 до 120 лет.' });
  }
  if (avatar && (!/^data:image\\/(png|jpeg|webp|gif);base64,/i.test(avatar) || avatar.length > 1500000)) {
    return res.status(400).json({ error: 'Фото должно быть JPG, PNG, WEBP или GIF размером до 1 МБ.' });
  }
  db.prepare('UPDATE users SET name = ?, age = ?, avatar = ? WHERE id = ?')
    .run(name, age, avatar, req.session.userId);
  res.json({ user: publicUser(userById(req.session.userId)) });
});

app.get(PREFIX + '/api/feed', needAuth, (req, res) => {
  const posts = db.prepare(
    'SELECT p.*, u.name, u.login, u.avatar FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.id DESC LIMIT 60'
  ).all();
  if (!posts.length) return res.json({ posts: [] });
  const ids = posts.map(post => post.id);
  const marks = ids.map(() => '?').join(',');
  const comments = db.prepare(
    'SELECT c.*, u.name, u.login FROM comments c JOIN users u ON u.id = c.user_id WHERE c.post_id IN (' + marks + ') ORDER BY c.id'
  ).all(...ids);
  const byPost = new Map();
  for (const comment of comments) {
    if (!byPost.has(comment.post_id)) byPost.set(comment.post_id, []);
    byPost.get(comment.post_id).push(comment);
  }
  res.json({ posts: posts.map(post => ({ ...post, comments: byPost.get(post.id) || [] })) });
});

app.post(PREFIX + '/api/posts', needAuth, writeLimit, (req, res) => {
  const body = clean(req.body && req.body.body);
  if (!body || body.length > 2000) return res.status(400).json({ error: 'Пост должен содержать от 1 до 2000 символов.' });
  db.prepare('INSERT INTO posts(user_id, body) VALUES(?, ?)').run(req.session.userId, body);
  res.status(201).json({ ok: true });
});

app.post(PREFIX + '/api/posts/:id/comments', needAuth, writeLimit, (req, res) => {
  const body = clean(req.body && req.body.body);
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1 || !body || body.length > 500) {
    return res.status(400).json({ error: 'Комментарий должен содержать от 1 до 500 символов.' });
  }
  if (!db.prepare('SELECT id FROM posts WHERE id = ?').get(id)) {
    return res.status(404).json({ error: 'Пост уже не существует.' });
  }
  db.prepare('INSERT INTO comments(post_id, user_id, body) VALUES(?, ?, ?)')
    .run(id, req.session.userId, body);
  res.status(201).json({ ok: true });
});

app.get(PREFIX + '/api/chats', needAuth, (req, res) => {
  const id = req.session.userId;
  const users = db.prepare(\`
    SELECT u.id, u.login, u.name, u.age, u.avatar, MAX(m.id) AS last_id
    FROM messages m
    JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
    WHERE m.sender_id = ? OR m.receiver_id = ?
    GROUP BY u.id
    ORDER BY last_id DESC
    LIMIT 100
  \`).all(id, id, id);
  res.json({ users: users.map(publicUser) });
});

app.get(PREFIX + '/api/messages/:id', needAuth, (req, res) => {
  const other = Number(req.params.id);
  const me = req.session.userId;
  if (!Number.isSafeInteger(other) || other < 1 || other === me || !userById(other)) {
    return res.status(404).json({ error: 'Собеседник не найден.' });
  }
  const messages = db.prepare(\`
    SELECT m.*, s.name AS sender_name
    FROM messages m
    JOIN users s ON s.id = m.sender_id
    WHERE (m.sender_id = ? AND m.receiver_id = ?)
       OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.id DESC
    LIMIT 300
  \`).all(me, other, other, me).reverse();
  res.json({ messages });
});

app.post(PREFIX + '/api/messages/:id', needAuth, writeLimit, (req, res) => {
  const body = clean(req.body && req.body.body);
  const other = Number(req.params.id);
  if (!Number.isSafeInteger(other) || other < 1 || other === req.session.userId || !userById(other)) {
    return res.status(400).json({ error: 'Не удалось найти собеседника.' });
  }
  if (!body || body.length > 2000) return res.status(400).json({ error: 'Сообщение должно содержать от 1 до 2000 символов.' });
  db.prepare('INSERT INTO messages(sender_id, receiver_id, body) VALUES(?, ?, ?)')
    .run(req.session.userId, other, body);
  res.status(201).json({ ok: true });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Не удалось прочитать данные формы. Обнови страницу и попробуй снова.' });
  }
  console.error('[social]', err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'На сервере произошла ошибка. Попробуй ещё раз чуть позже.' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log('Social app listening on 127.0.0.1:' + PORT);
});
