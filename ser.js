require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');

const User = require('./api/models/user');

const app = express();

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection failed:', err);
});


const jwtSecret = process.env.JWT_SECRET 

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: jwtSecret,
};

passport.use(
  new JwtStrategy(jwtOptions, async (payload, done) => {
    try {
      const user = await User.findById(payload.id);
      if (!user) {
        return done(null, false);
      }
      return done(null, user);
    } catch (err) {
      return done(err, false);
    }
  })
);

const signup = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      return res.status(401).json({ message: 'Email already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email, password: hash });

    return res.json({
      user: newUser,
      message: 'User created successfully',
    });
  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
};

passport.use(
  new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return done(null, false, { message: 'User not found' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: 'Invalid password' });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  if (user) {
    return done(null, user.id);
  }
  return done(null, false);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware
app.use(express.json());
app.use(passport.initialize());

app.post('/signup', signup);

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Authentication failed' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    const payload = {
      id: user._id,
      email: user.email,
    };

    jwt.sign(payload, jwtSecret, { expiresIn: '1h' }, (tokenErr, token) => {
      if (tokenErr) {
        return res.status(500).json({ message: 'JWT creation failed' });
      }

      return res.status(200).json({
        message: 'Login successful',
        token: token,
      });
    });
  })(req, res, next);
});

app.get('/checkauth', passport.authenticate('jwt',{session:false}), (req, res)=>{
    res.json(req.user)
})

app.post('/logout', (req, res) => {
  req.logout();
  res.send('User logout successful');
});

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});
