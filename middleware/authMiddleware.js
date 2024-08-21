const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Tenant = require("../models/Tenant");
const { logAction } = require("../utils/logger");
const sanitize = require("sanitize-html");
require("dotenv").config();

// Middleware to verify a user's role
exports.verifyRole = (roles) => {
  return async (req, res, next) => {
    try {
      // Extract and sanitize the token from the Authorization header
      const token = sanitize(
        req.header("Authorization").replace("Bearer ", "")
      );

      // Verify the token and decode the payload
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      logAction(
        "Decoded Token",
        `User ID: ${decoded._id}, Roles: ${roles.join(", ")}`
      );

      // Find the user by the ID in the token payload
      const user = await User.findById(decoded._id).populate("tenant");
      if (!user) {
        logAction("Access Denied", `User not found for ID: ${decoded._id}`);
        return res.status(403).json({ error: "Access denied" });
      }

      // Check if the user has one of the required roles
      if (!roles.includes(user.role)) {
        logAction(
          "Access Denied",
          `User ${user.username} does not have the required role`
        );
        return res.status(403).json({ error: "Access denied" });
      }

      // Attach the user and tenant to the request object for further use
      req.user = user;
      req.tenant = user.tenant;
      next();
    } catch (error) {
      logAction("Error Verifying Role", error.message);
      res.status(403).json({ error: "Access denied", details: error.message });
    }
  };
};

exports.verifyUser = async (req, res, next) => {
  try {
    // Extract and sanitize the token from the Authorization header
    const token = sanitize(req.header("Authorization"));

    if (!token) {
      logAction("No Token Provided", "Authorization header missing");
      return res.status(403).json({ error: "No token provided" });
    }

    // Verify the token and decode the payload
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    logAction("Decoded Token", `User ID: ${decoded._id}`);

    // Find the user by the ID in the token payload and populate the tenant
    const user = await User.findById(decoded._id).populate("tenant");
    if (!user) {
      logAction("Invalid Token", `User not found for ID: ${decoded._id}`);
      return res.status(403).json({ error: "Invalid token" });
    }

    // Attach the user and tenant to the request object for further use
    req.user = user;
    req.tenant = user.tenant;
    next();
  } catch (error) {
    logAction("Error Verifying User", error.message);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};
exports.verifyTenant = async (req, res, next) => {
  try {
    const apiKey = req.header("x-api-key");

    if (!apiKey) {
      return res.status(403).json({ error: "No API key provided" });
    }

    const tenant = await Tenant.findOne({ apiKey });
    if (!tenant) {
      return res.status(403).json({ error: "Invalid API key" });
    }

    req.tenant = tenant;
    next();
  } catch (error) {
    res.status(500).json({ error: "Server error", details: error.message });
  }
};

