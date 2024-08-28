const jwt = require("jsonwebtoken");
const User = require("../models/User");
const sanitize = require("sanitize-html");

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
      const token = sanitize(authHeader.replace("Bearer ", "").trim());

      // Verify JWT token
      let decoded;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
      } catch (err) {
        console.error("JWT verification failed:", err.message);
        return res.status(401).json({ error: "Invalid token." });
      }

      // Retrieve user by ID from the decoded token
      const user = await User.findById(decoded.userId).populate("tenant"); // Ensure that the field matches your model

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
      console.error("Error in verifyRole middleware:", error.message);
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
    // Verify the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    console.log("Decoded JWT payload:", decoded); // Log the decoded token payload

    // Fetch the complete user details from the database
    const user = await User.findById(decoded.userId).populate("tenant");

    // Check if user exists
    if (!user) {
      console.log("User not found with ID:", decoded.userId);
      return res.status(404).json({ error: "User not found." });
    }

    // Attach the full user object to the request
    req.user = { userId: user._id, tenantId: user.tenant._id }; // Ensure both values are set correctly
    console.log("User attached to request:", req.user);

    next();
  } catch (error) {
    console.error("Error in verifyUser middleware:", error.message);
    res.status(500).json({ error: "Internal server error." });
  }
};