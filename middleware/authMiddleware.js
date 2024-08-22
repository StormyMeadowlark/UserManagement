const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { logAction } = require("../utils/logger");
const sanitize = require("sanitize-html");

exports.verifyRole = (roles) => {
  return async (req, res, next) => {
    try {
      const token = sanitize(
        req.header("Authorization").replace("Bearer ", "")
      );
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const user = await User.findById(decoded._id).populate("tenant");
      if (
        !user ||
        !roles.includes(user.role) ||
        !user.tenant.equals(req.tenant._id)
      ) {
        return res.status(403).json({ error: "Access denied" });
      }

      req.user = user;
      next();
    } catch (error) {
      logAction("Error Verifying Role", error.message);
      res.status(403).json({ error: "Access denied", details: error.message });
    }
  };
};
