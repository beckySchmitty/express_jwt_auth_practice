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
  const result = await db.query(`INSERT INTO users (username, password)
  VALUES ($1, $2) 
  RETURNING username `, [username, hashedPwd]);

  return res.json(result.rows[0])
} catch(e) {
  if (e.code === '23505') {
    return next(new ExpressError("username taken, pick another", 400));
  }
  return next(e)
}

})



module.exports = router;

