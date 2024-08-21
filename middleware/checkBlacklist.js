const BlacklistedToken = require("../models/BlacklistedToken");
const { logAction } = require("../utils/logger");
const sanitize = require("sanitize-html");

const checkBlacklist = async (req, res, next) => {
  try {
    // Extract and sanitize the token from the Authorization header
    const token = sanitize(req.header("Authorization").replace("Bearer ", ""));

    if (!token) {
      logAction(
        "Token Missing",
        "No token provided in the Authorization header"
      );
      return res.status(401).json({ error: "Token is missing" });
    }

    // Check if the token is blacklisted
    const blacklisted = await BlacklistedToken.findOne({ token });

    if (blacklisted) {
      logAction("Blacklisted Token", `Token is blacklisted: ${token}`);
      return res.status(401).json({ error: "Token is blacklisted" });
    }

    logAction("Token Check Passed", `Token is not blacklisted: ${token}`);
    next();
  } catch (error) {
    logAction("Error Checking Blacklist", error.message);
    console.error("Error checking blacklist:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
};

module.exports = checkBlacklist;
