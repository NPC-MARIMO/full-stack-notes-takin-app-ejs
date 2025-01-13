require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { Schema } = mongoose;

const app = express();
const port = process.env.PORT || 3000;

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Schemas and Models
const userSchema = new Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const noteSchema = new Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Note = mongoose.model('Note', noteSchema);

// Middleware
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
}));
app.use(flash());

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
};

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/login', (req, res) => {
  res.render('login', { messages: req.flash() });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.passwordHash)) {
      req.session.user = { id: user._id, email: user.email };
      res.redirect('/notes');
    } else {
      req.flash('error', 'Invalid credentials');
      res.redirect('/login');
    }
  } catch (error) {
    req.flash('error', 'An error occurred');
    res.redirect('/login');
  }
});

app.get('/register', (req, res) => {
  res.render('register', { messages: req.flash() });
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, passwordHash: hashedPassword });
    await user.save();

    req.session.user = { id: user._id, email: user.email };
    res.redirect('/notes');
  } catch (error) {
    req.flash('error', 'Registration failed');
    res.redirect('/register');
  }
});

app.get('/notes', requireAuth, async (req, res) => {
  try {
    const notes = await Note.find({ userId: req.session.user.id }).sort({ createdAt: -1 });
    res.render('notes', { notes, user: req.session.user });
  } catch (error) {
    req.flash('error', 'Failed to fetch notes');
    res.redirect('/');
  }
});

app.post('/notes', requireAuth, async (req, res) => {
  const { title, content } = req.body;

  try {
    const note = new Note({
      userId: req.session.user.id,
      title,
      content,
    });
    await note.save();

    res.redirect('/notes');
  } catch (error) {
    req.flash('error', 'Failed to create note');
    res.redirect('/notes');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
