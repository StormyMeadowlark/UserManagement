const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { logAction } = require("../utils/logger");
const sanitize = require("sanitize-html");
const dotenv = require("dotenv");
dotenv.config();

exports.verifyRole = (roles) => {
  return async (req, res, next) => {
    try {
      // Extract and sanitize the token from the Authorization header
      const authHeader = req.header("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        logAction(
          "Authorization Header Missing",
          "No Authorization header or incorrect format"
        );
        return res.status(401).json({ error: "Unauthorized" });
      }

      const token = sanitize(authHeader.replace("Bearer ", ""));
      logAction("Token Extraction", `Extracted token: ${token}`);

      // Verify the token and decode the payload
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      logAction("Token Decoding", `Decoded token for user ID: ${decoded._id}`);

      // Find the user by the ID in the token payload and populate the tenant
      const user = await User.findById(decoded._id).populate("tenant");

      if (!user) {
        logAction("User Not Found", `No user found with ID: ${decoded._id}`);
        return res.status(403).json({ error: "Access denied" });
      }

      logAction(
        "User Found",
        `User ${user.username} found with role: ${user.role}`
      );

      // Ensure that user and tenant exist and check the role
      if (!roles.includes(user.role)) {
        logAction(
          "Role Mismatch",
          `User role: ${user.role} does not match required roles: ${roles.join(
            ", "
          )}`
        );
        return res.status(403).json({ error: "Access denied" });
      }

      // Ensure that the tenant is properly populated
      if (!user.tenant) {
        logAction(
          "Tenant Missing",
          `User ${user.username} has no tenant associated`
        );
        return res.status(403).json({ error: "Access denied" });
      }

      if (!req.tenant) {
        logAction(
          "Request Tenant Missing",
          `Request is missing tenant information`
        );
        return res.status(403).json({ error: "Access denied" });
      }

      if (user.tenant._id.toString() !== req.tenant._id.toString()) {
        logAction(
          "Tenant Mismatch",
          `User tenant ID: ${user.tenant._id} does not match request tenant ID: ${req.tenant._id}`
        );
        return res.status(403).json({ error: "Access denied" });
      }

      // Attach the user to the request object for further use
      req.user = user;
      logAction("Access Granted", `User ${user.username} granted access`);
      next();
    } catch (error) {
      console.error("Error in verifyRole middleware:", error.message);
      res.status(500).json({ error: "Internal server error" });
    }
  };
};

exports.verifyUser = async (req, res, next) => {
  try {
    const token = req.header("Authorization").replace("Bearer ", "");
    console.log("Token:", token);

    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded Token:", decoded);

    const user = await User.findById(decoded._id);
    console.log("User:", user);

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Error in verifyUser middleware:", error.message);
    res
      .status(401)
      .json({ error: "Unauthorized access", details: error.message });
  }
};