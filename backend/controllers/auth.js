const bcrypt = require('bcrypt');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Register a new user
exports.registerUser = async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
};

// User login
exports.loginUser = (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(400).json({ error: 'Login failed' });
    }
    req.login(user, { session: false }, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Login failed' });
      }
      const token = jwt.sign({ id: user._id }, 'your-secret-key');
      return res.json({ token });
    });
  })(req, res, next);
};

// Authentication middleware
exports.authenticateUser = passport.authenticate('jwt', { session: false });
