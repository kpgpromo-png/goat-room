const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3078);
const PREFIX = '/social';
const db = new Database(process.env.DB_FILE || path.join(__dirname, 'social.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
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
`);

app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(session({
 secret: process.env.SESSION_SECRET || 'CHANGE_THIS_SECRET_BEFORE_PUBLIC_USE',
 resave: false,
 saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', maxAge: 7 * 86400000 }
}));
app.use(PREFIX, express.static(path.join(__dirname, 'public')));
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const clean = v => String(v || '').trim();
const publicUser = u => ({ id: u.id, login: u.login, name: u.name, age: u.age, avatar: u.avatar || '' });
const userById = id => db.prepare('SELECT id,login,name,age,avatar FROM users WHERE id=?').get(id);
const needAuth = (req,res,next) => req.session.userId ? next() : res.status(401).json({error:'Сначала войдите в аккаунт'});
app.use((req,res,next) => { res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Referrer-Policy','same-origin'); next(); });

app.post(PREFIX+'/api/register', authLimit, async (req,res) => {
 const login=clean(req.body.login).toLowerCase(), password=String(req.body.password||''), name=clean(req.body.name), age=Number(req.body.age);
 if (!/^[a-z0-9_]{3,24}$/.test(login)) return res.status(400).json({error:'Логин: 3–24 символа, латиница, цифры и _'});
 if (password.length<8 || password.length>100) return res.status(400).json({error:'Пароль должен быть от 8 символов'});
 if (!name || name.length>40 || !Number.isInteger(age) || age<13 || age>120) return res.status(400).json({error:'Проверьте имя и возраст (13–120)'});
 try {
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare('INSERT INTO users(login,password_hash,name,age) VALUES(?,?,?,?)').run(login,hash,name,age);
  req.session.userId=Number(info.lastInsertRowid);
  res.json({user:publicUser(userById(req.session.userId))});
 } catch(e) { res.status(409).json({error:'Этот логин уже занят'}); }
});
app.post(PREFIX+'/api/login', authLimit, async (req,res) => {
 const login=clean(req.body.login), u=db.prepare('SELECT * FROM users WHERE login=? COLLATE NOCASE').get(login);
 if (!u || !(await bcrypt.compare(String(req.body.password||''),u.password_hash))) return res.status(401).json({error:'Неверный логин или пароль'});
 req.session.userId=u.id; res.json({user:publicUser(u)});
});
app.post(PREFIX+'/api/logout', (req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get(PREFIX+'/api/me', (req,res)=>res.json({user:req.session.userId?publicUser(userById(req.session.userId)):null}));
app.get(PREFIX+'/api/users', needAuth, (req,res)=>{
 const q=clean(req.query.q).slice(0,40);
 const users=db.prepare("SELECT id,login,name,age,avatar FROM users WHERE login LIKE ? OR name LIKE ? ORDER BY name LIMIT 30").all('%'+q+'%','%'+q+'%');
 res.json({users:users.map(publicUser)});
});
app.get(PREFIX+'/api/users/:id', needAuth, (req,res)=>{
 const u=userById(Number(req.params.id)); if(!u) return res.status(404).json({error:'Пользователь не найден'});
 const posts=db.prepare('SELECT p.*,u.name,u.login,u.avatar FROM posts p JOIN users u ON u.id=p.user_id WHERE p.user_id=? ORDER BY p.id DESC LIMIT 50').all(u.id);
 res.json({user:publicUser(u),posts});
});
app.put(PREFIX+'/api/profile', needAuth, (req,res)=>{
 const name=clean(req.body.name), age=Number(req.body.age), avatar=String(req.body.avatar||'');
 if(!name||name.length>40||!Number.isInteger(age)||age<13||age>120) return res.status(400).json({error:'Проверьте имя и возраст'});
 if(avatar && (!/^data:image\/(png|jpeg|webp|gif);base64,/.test(avatar)||avatar.length>1500000)) return res.status(400).json({error:'Фото должно быть JPG, PNG, WEBP или GIF до 1 МБ'});
 db.prepare('UPDATE users SET name=?,age=?,avatar=? WHERE id=?').run(name,age,avatar,req.session.userId);
 res.json({user:publicUser(userById(req.session.userId))});
});
app.get(PREFIX+'/api/feed', needAuth, (req,res)=>{
 const posts=db.prepare('SELECT p.*,u.name,u.login,u.avatar FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 60').all();
 const comments=db.prepare('SELECT c.*,u.name,u.login FROM comments c JOIN users u ON u.id=c.user_id ORDER BY c.id').all();
 res.json({posts:posts.map(p=>({...p,comments:comments.filter(c=>c.post_id===p.id)}))});
});
app.post(PREFIX+'/api/posts', needAuth, (req,res)=>{
 const body=clean(req.body.body); if(!body||body.length>2000) return res.status(400).json({error:'Пост должен быть до 2000 символов'});
 db.prepare('INSERT INTO posts(user_id,body) VALUES(?,?)').run(req.session.userId,body); res.json({ok:true});
});
app.post(PREFIX+'/api/posts/:id/comments', needAuth, (req,res)=>{
 const body=clean(req.body.body), id=Number(req.params.id);
 if(!body||body.length>500||!db.prepare('SELECT id FROM posts WHERE id=?').get(id)) return res.status(400).json({error:'Проверьте комментарий'});
 db.prepare('INSERT INTO comments(post_id,user_id,body) VALUES(?,?,?)').run(id,req.session.userId,body); res.json({ok:true});
});
app.get(PREFIX+'/api/chats', needAuth, (req,res)=>{
 const id=req.session.userId;
 const users=db.prepare(`SELECT u.id,u.login,u.name,u.age,u.avatar, MAX(m.id) last_id
 FROM messages m JOIN users u ON u.id=CASE WHEN m.sender_id=? THEN m.receiver_id ELSE m.sender_id END
 WHERE m.sender_id=? OR m.receiver_id=? GROUP BY u.id ORDER BY last_id DESC`).all(id,id,id);
 res.json({users:users.map(publicUser)});
});
app.get(PREFIX+'/api/messages/:id', needAuth, (req,res)=>{
 const other=Number(req.params.id), me=req.session.userId;
 if(!userById(other)) return res.status(404).json({error:'Пользователь не найден'});
 const messages=db.prepare(`SELECT m.*,s.name sender_name FROM messages m JOIN users s ON s.id=m.sender_id
 WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY m.id LIMIT 300`).all(me,other,other,me);
 res.json({messages});
});
app.post(PREFIX+'/api/messages/:id', needAuth, (req,res)=>{
 const body=clean(req.body.body), other=Number(req.params.id);
 if(!body||body.length>2000||!userById(other)||other===req.session.userId) return res.status(400).json({error:'Не удалось отправить сообщение'});
 db.prepare('INSERT INTO messages(sender_id,receiver_id,body) VALUES(?,?,?)').run(req.session.userId,other,body); res.json({ok:true});
});
app.listen(PORT,'127.0.0.1',()=>console.log('Social app listening on 127.0.0.1:'+PORT));
