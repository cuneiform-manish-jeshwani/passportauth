
require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt= require('bcrypt')

const User = require('./api/models/user')

const app = express();

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection failed:', err);
});


const signup= async (req, res) => {
    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (user) {
        return res.status(401).json({ message: "emailAll ready exists" });
      }

      const hash = await bcrypt.hash(password, 10);
      const newuser = await User.create({ email, password: hash});

      return res.json({
        user:newuser,
        message: "User created successfully ",
      });
    } catch (err) {
      return res.json({ success: false, message: err.message });
    }
  }

passport.use(
  new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    console.log(email, password)
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return done(null, false, { message: 'User not found' });
      }

    //   if (!user.password==password) {
    //     return done(null, false, { message: 'WRONG PASSWORD' });
    //   }

    const isMatch = await bcrypt.compare(password, user.password);
          if (!isMatch) {
            return res.status(401).json({message: "invalid password"})
          }
   


     console.log(user)
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
    if(user){
        return  done(null, user.id);
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

// app.use(
//   session({
//     secret: 'worked',
//     resave: false,
//     saveUninitialized: false,
//   })
//);
app.use(passport.initialize());
//app.use(passport.session());



app.post('/signup', signup)


// app.post('/login', 
//   passport.authenticate('local'),function(req, res){
//     res.json(req.user)
//   });

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Authentication failed' });
      }
      if (!user) {
        return res.status(401).json({ message: 'Authentication failed' });
      }
  
      // Create a JWT payload with user data
      const payload = {
        id: user._id,
        email: user.email,
      };
  
     
      jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (tokenErr, token) => {
        if (tokenErr) {
          return res.status(500).json({ message: 'JWT creation failed' });
        }
  
        // Send the JWT as a response
        return res.status(200).json({
          message: 'Login successful',
          token: token,
          
        });
      });
    })(req, res, next);
  });



app.post('/logout', (req, res) => {
  req.logout();
  res.send('user logout success full');
});

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});
