const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");

// verifies user and sends token with req
function authenticateJWT(req, res, next) {
  try {
    const tokenFromBody = req.body._token;
    const payload = jwt.verify(tokenFromBody, SECRET_KEY);
    req.user = payload;
    console.log("YOU HAVE A VALID TOKEN")
    return next();
  } catch (e) {
    // error in middleware isn't error -- need to just say next() and if error above, will be pased on
    return next();
  }
}

// if there's a user it will call next, if not then error is thrown
function ensureLoggedIn(req, res, next) {
  if (!req.user) {
    const e = new ExpressError("Unauthorized", 401)
    return next(e);
  } else{
    // valid user
    return next();
  }
}

// if there's a user it will call next, if not then error is thrown
function ensureAdmin(req, res, next) {
  if (!req.user || req.user.type !== 'admin') {
    const e = new ExpressError("Unauthorized, must be an Admin to access", 401)
    return next(e);
  } else{
    // valid user
    return next();
  }
}
module.exports = {authenticateJWT, ensureLoggedIn, ensureAdmin};