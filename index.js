
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Hardcoded configuration values
const CLIENT_ID = 'YOUR_DISCORD_CLIENT_ID';
const CLIENT_SECRET = 'YOUR_DISCORD_CLIENT_SECRET';
const REDIRECT_URI = 'https://your-website-url.com/auth/discord/callback';
const SESSION_SECRET = 'some_random_secret_string';
const API_KEY = 'holy_vouch_secure_api_key_2024_production';
const MONGODB_URI = 'mongodb+srv://username:password@cluster.mongodb.net/holyvouch?retryWrites=true&w=majority';
const JWT_SECRET = 'your_jwt_secret_here_change_this_in_production';

const app = express();
const PORT = process.env.PORT || 5000;

// Import models
const User = require('./models/User');
const Vouch = require('./models/Vouch');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Passport Discord Strategy
passport.use(new DiscordStrategy({
  clientID: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  callbackURL: REDIRECT_URI,
  scope: ['identify', 'guilds']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ discordId: profile.id });
    
    if (!user) {
      user = new User({
        discordId: profile.id,
        username: profile.username,
        discriminator: profile.discriminator,
        avatar: profile.avatar,
        email: profile.email,
        vouchCount: 0,
        serverVouches: {}
      });
      await user.save();
    } else {
      // Update user info
      user.username = profile.username;
      user.discriminator = profile.discriminator;
      user.avatar = profile.avatar;
      await user.save();
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

// Middleware to check API key for bot endpoints
const requireApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(403).json({ error: 'Unauthorized - Invalid API key' });
  }
  next();
};

const requireAdmin = async (req, res, next) => {
  if (req.isAuthenticated() && req.user.isAdmin) {
    return next();
  }
  res.status(403).send('Access denied');
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Public profile route
app.get('/u/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
  } catch (error) {
    res.status(500).send('Server error');
  }
});

// Auth routes
app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
  passport.authenticate('discord', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Login failed' });
      }
      res.json({ success: true, redirect: '/dashboard' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      vouchCount: 0,
      serverVouches: {}
    });
    
    await user.save();
    
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Registration failed' });
      }
      res.json({ success: true, redirect: '/dashboard' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// API Routes
app.post('/api/vouch', requireApiKey, async (req, res) => {
  try {
    const { fromUserID, toUserID, serverID } = req.body;
    
    // Check if vouch already exists
    const existingVouch = await Vouch.findOne({ fromUserID, toUserID, serverID });
    if (existingVouch) {
      return res.status(400).json({ error: 'Vouch already exists from this user' });
    }
    
    const vouch = new Vouch({
      fromUserID,
      toUserID,
      serverID,
      timestamp: new Date()
    });
    
    await vouch.save();
    
    // Update user vouch counts
    const user = await User.findOne({ discordId: toUserID });
    if (user) {
      user.vouchCount += 1;
      if (!user.serverVouches[serverID]) {
        user.serverVouches[serverID] = 0;
      }
      user.serverVouches[serverID] += 1;
      await user.save();
    }
    
    res.json({ success: true, vouch });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/vouches/:userid', async (req, res) => {
  try {
    const user = await User.findOne({ discordId: req.params.userid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const vouches = await Vouch.find({ toUserID: req.params.userid });
    res.json({ 
      totalVouches: user.vouchCount, 
      serverVouches: user.serverVouches,
      vouches 
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/stats/global', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalVouches = await Vouch.countDocuments();
    const recentVouches = await Vouch.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .populate('fromUserID toUserID');
    
    res.json({ 
      totalUsers, 
      totalVouches, 
      recentVouches 
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user/me', requireAuth, (req, res) => {
  res.json({
    id: req.user._id,
    username: req.user.username,
    discordId: req.user.discordId,
    avatar: req.user.avatar,
    vouchCount: req.user.vouchCount,
    serverVouches: req.user.serverVouches,
    isAdmin: req.user.isAdmin || false
  });
});

app.get('/api/user/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      username: user.username,
      avatar: user.avatar,
      vouchCount: user.vouchCount,
      serverVouches: user.serverVouches
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin API routes
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/vouches', requireAdmin, async (req, res) => {
  try {
    const vouches = await Vouch.find().sort({ timestamp: -1 });
    res.json(vouches);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Holy Vouch server running on port ${PORT}`);
});
