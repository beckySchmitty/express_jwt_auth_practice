const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");


function authenticateJWT(req, res, next) {
  try {

    return next();
  } catch (e) {
    return next();
  }
}
