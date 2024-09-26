const jwt = require("jsonwebtoken");
const mongoose = require("mongoose"); // Ensure mongoose is imported
const User = require("../models/User");

exports.verifyRole = (roles) => {
  return async (req, res, next) => {
    try {
      const authHeader = req.header("Authorization");

      // Check if Authorization header is present and formatted correctly
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res
          .status(401)
          .json({ error: "Unauthorized: No token provided." });
      }

      // Extract and sanitize the token
      const token = authHeader.replace("Bearer ", "").trim();

      // Verify JWT token
      let decoded;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
      } catch (err) {
        console.error("JWT verification failed:", err.message);
        return res.status(401).json({ error: "Invalid token." });
      }

      // Retrieve user by ID from the decoded token
      const user = await User.findById(decoded.userId).populate("tenant");

      // Check if user exists and has a permitted role
      if (!user) {
        return res.status(404).json({ error: "User not found." });
      }

      if (!roles.includes(user.role)) {
        return res
          .status(403)
          .json({ error: "Access denied: Insufficient permissions." });
      }

      // Attach user details to the request object for later use
      req.user = user;
      next();
    } catch (error) {
      console.error("Error in verifyRole middleware:", error.message, {
        url: req.originalUrl, // log the request URL
        method: req.method, // log the request method
      });
      res.status(500).json({ error: "Internal server error." });
    }
  };
};

exports.verifyUser = async (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Authorization header missing or malformed." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded JWT payload:", decoded);

    const userId = new mongoose.Types.ObjectId(decoded.userId); // Ensure this is correctly created
    const tenantId = new mongoose.Types.ObjectId(decoded.tenantId);

    console.log("Querying user with ID:", userId);
    const user = await User.findById(userId).populate("tenant");

    console.log("Fetched user:", user); // Log the fetched user document

    if (!user) {
      console.log("User not found with ID:", userId);
      return res.status(404).json({ error: "User not found." });
    }

    req.user = { userId: user._id, tenantId: user.tenant._id };
    console.log("User attached to request:", req.user);

    next();
  } catch (error) {
    console.error("Error in verifyUser middleware:", error.message, {
      url: req.originalUrl,
      method: req.method,
    });

    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ error: "Token expired. Please login again." });
    }

    res.status(500).json({ error: "Internal server error." });
  }
};
