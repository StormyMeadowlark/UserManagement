const jwt = require("jsonwebtoken");
const User = require("../models/User");
const sanitize = require("sanitize-html");

exports.verifyRole = (roles) => {
  return async (req, res, next) => {
    try {
      const authHeader = req.header("Authorization");

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const token = sanitize(authHeader.replace("Bearer ", ""));

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const user = await User.findById(decoded._id).populate("tenant");

      if (!user || !roles.includes(user.role)) {
        return res.status(403).json({ error: "Access denied" });
      }

      req.user = user;
      next();
    } catch (error) {
      console.error("Error in verifyRole middleware:", error.message);
      res.status(500).json({ error: "Internal server error" });
    }
  };
};


exports.verifyUser = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Authorization header missing or malformed." });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid token." });
    }

    req.user = decoded; // Attach the decoded token information to the req object
    next();
  });
};