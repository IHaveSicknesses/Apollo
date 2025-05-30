// server.js
const express = require('express');
const http = require('http');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Server } = require('socket.io');
const mongoose = require('mongoose');

require('dotenv').config();

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());

// --- MongoDB Setup ---
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected')).catch(err => console.error(err));

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
});

const MessageSchema = new mongoose.Schema({
  from: String,
  to: String,
  text: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);

// --- JWT Secret ---
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// --- Auth Routes ---

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ msg: 'Missing username or password' });
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ username, passwordHash });
    await user.save();
    res.json({ msg: 'User created' });
  } catch (e) {
    if (e.code === 11000) return res.status(400).json({ msg: 'Username already taken' });
    res.status(500).json({ msg: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ msg: 'Missing username or password' });
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ msg: 'Invalid username or password' });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).json({ msg: 'Invalid username or password' });
  const token = jwt.sign({ username }, JWT_SECRET);
  res.json({ token, username });
});

// Middleware to verify token from socket handshake
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// --- Socket.IO setup ---
const io = new Server(server, {
  cors: {
    origin: '*',
  }
});

const onlineUsers = new Map(); // username -> socket.id

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const userData = verifyToken(token);
  if (!userData) return next(new Error('Authentication error'));
  socket.user = userData;
  next();
});

io.on('connection', (socket) => {
  const username = socket.user.username;
  onlineUsers.set(username, socket.id);

  console.log(username, 'connected');

  socket.on('private message', async ({ to, text }) => {
    // Save message in DB
    const message = new Message({ from: username, to, text });
    await message.save();

    // Send message to recipient if online
    const toSocketId = onlineUsers.get(to);
    if (toSocketId) {
      io.to(toSocketId).emit('private message', { from: username, text });
    }

    // Also emit back to sender for confirmation
    socket.emit('private message', { from: username, to, text });
  });

  socket.on('load messages', async ({ withUser }) => {
    // Load last 50 messages between these two users
    const messages = await Message.find({
      $or: [
        { from: username, to: withUser },
        { from: withUser, to: username }
      ]
    }).sort({ createdAt: 1 }).limit(50);
    socket.emit('load messages', messages);
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(username);
    console.log(username, 'disconnected');
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
