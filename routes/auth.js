// Routes for demonstrating authentication in Express
const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { ensureLoggedIn, ensureAdmin } = require("../middleware/auth");

router.get('/', (req, res, next) => {
  res.send("APP IS WORKING!!!")
})


router.post('/register', async (req, res, next) => {
try {
  const {username, password} = req.body;
  if (!username || !password) {
    throw new ExpressError("username and password required", 400)
  }
  const hashedPwd = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
  // save to db
  const results = await db.query(`INSERT INTO users (username, password)
  VALUES ($1, $2) 
  RETURNING username `, [username, hashedPwd]);

  return res.json(results.rows[0])
} catch(e) {
  if (e.code === '23505') {
    return next(new ExpressError("username taken, pick another", 400));
  }
  return next(e)
}
})

// using this for the example but usually this would change based on what the user is logging in as
const userType = "admin"

router.post('/login', async (req, res, next) => {
  try {
    const {username, password} = req.body;
    if (!username || !password) {
      throw new ExpressError("username and password required", 400)
    }
    const results = await db.query(`SELECT username, password 
    FROM users 
    WHERE username=$1`, [username]);
    const user = results.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({username, type: userType }, SECRET_KEY)
        return res.json({message: `Welcome back ${user.username}`, token})
      }
    }
    throw new ExpressError("Invalid username/password", 400)
  } catch(e) {
    return next(e)
  }
  })

  // public facing API would specifiy how to send token, no standard, standard is just that tokens are used
  // this will have front-end sending _token within req body
  // tested with insomnia
  router.get('/topsecret', ensureLoggedIn, async (req, res, next) => {
    try {
      // const token = req.body._token;
      // const payload = jwt.verify(token, SECRET_KEY);
      // removed the two above lines by adding ensureLoggedIn middleware to check user auth (can be applied to more routies easily)
      return res.json({msg: "SIGNED IN"})
    } catch(e) {
      return next(new ExpressError("Please login first", 401))
    }
    })

  router.get('/vip', ensureLoggedIn, async (req, res, next) => {
      return res.json({msg: `Hello, ${req.user.username}! Welcome to our VIP page.`})
    })   
    
  router.get('/adminhome', ensureAdmin, async (req, res, next) => {
      return res.json({msg: `Hello, ${req.user.username}! Congrats on being an Admin.`})
    })
  



module.exports = router;


// best way to refactor would be to create user model so we could call user.login or user.register

