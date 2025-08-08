// asc_backend/server.js
// Simple Express backend for Ascendia

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory stores (replace with DB in production)
const users = {}; // { email: { passwordHash, id } }
const essays = []; // { userId, essayText, submittedAt }

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'ascendia_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Helper: require login
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Routes

// Signup
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (users[email]) {
    return res.status(409).json({ error: 'User already exists' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const userId = crypto.randomUUID();
  users[email] = { passwordHash, id: userId };
  req.session.userId = userId;
  res.json({ message: 'User created', userId });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user.id;
  res.json({ message: 'Logged in' });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out' });
});

// Submit Essay
app.post('/submit-essay', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const { essay } = req.body;
  if (!essay || essay.trim().length < 50) {
    return res.status(400).json({ error: 'Essay text too short' });
  }
  essays.push({ userId, essayText: essay, submittedAt: new Date() });
  res.json({ message: 'Essay submitted for review' });
});

// Get submitted essays (admin/instructor view)
app.get('/essays', (req, res) => {
  // In production, restrict to instructors
  res.json(essays);
});

// Start server
app.listen(PORT, () => {
  console.log(`Ascendia backend running on port ${PORT}`);
});
