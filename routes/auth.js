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
        return res.json({message: `Welcome back ${user.username}`})
      }
    }
    throw new ExpressError("Invalid username/password", 400)
  } catch(e) {
    return next(e)
  }
  })
  



module.exports = router;

