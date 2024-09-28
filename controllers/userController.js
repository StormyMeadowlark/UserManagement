const User = require("../models/User");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { logAction } = require("../utils/logger");
const { sendEmail } = require("../utils/email");
const { hashPassword, comparePassword } = require("../utils/hash");
const s3 = require("../utils/digitalOcean");
const path = require("path");
const { generateApiKey } = require("../utils/apiKeyUtil");
const { validationResult } = require("express-validator");
const sanitize = require("sanitize-html");
const { encrypt } = require("../config/config");
require("dotenv").config();
const Tenant = require("../models/Tenant")
const bcrypt = require("bcrypt")
const mongoose = require("mongoose");
const ApiKey = require("../models/ApiKey");
const validator = require("validator");

exports.registerUser = async (req, res) => {
  try {
    const { username, email, password, tenant, role } = req.body;

    // Check if all required fields are provided
    if (!username || !email || !password || !tenant) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Validate password strength
    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters long" });
    }

    // Check if the tenant exists
    const tenantObj = await Tenant.findOne({ name: tenant });
    if (!tenantObj) {
      return res.status(400).json({ error: "Invalid tenant name" });
    }

    // Ensure the check is only done within the context of the tenant
    const existingUser = await User.findOne({
      email: email,
      tenant: tenantObj._id,
    });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Email already exists for this tenant" });
    }

    // Generate a verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");

    // Create a new user within the tenant
    const newUser = new User({
      username,
      email,
      role: role || "Viewer", // Default role if not provided
      password,
      tenant: tenantObj._id,
      verificationToken,
    });

    // Save the new user
    await newUser.save();

    const verificationUrl = `${tenantObj.domain}/verify?token=${verificationToken}&tenantId=${tenantObj._id}`;

    // Send verification email
    await sendEmail(
      newUser.email,
      tenantObj.verifiedSenderEmail,
      "Email Verification",
      `Please verify your email by clicking on the following link:\n\n${verificationUrl}`,
      tenantObj.sendGridApiKey
    );

    // Success response
    res
      .status(201)
      .json({
        message:
          "User registered successfully. Please check your email to verify your account.",
      });
  } catch (error) {
    if (error.code === 11000) {
      return res
        .status(400)
        .json({ error: "Email already exists for this tenant" });
    }
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};


exports.loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;
    const tenantId = req.headers["x-tenant-id"];

    if (!tenantId) {
      return res.status(400).json({ error: "Tenant ID is required" });
    }

    console.log("Incoming login request:", { username, tenantId });

    const user = await User.findOne({ username, tenant: tenantId });
    console.log("Retrieved user:", user); // Log the retrieved user

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Log the user's password stored in the database for comparison (only for debugging purposes)
    console.log("User password from DB:", user.password); // Log hashed password

    const isMatch = await user.comparePassword(password);
    console.log("Password match result:", isMatch); // Log result of password comparison

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { userId: user._id, tenantId },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    // Include necessary user data in the response
    const userData = {
      _id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      emailVerified: user.emailVerified,
    };

    res.status(200).json({
      token,
      user: userData,
      message: "Login successful",
    });
  } catch (error) {
    console.error("Error logging in:", error.message);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};
exports.verifyEmail = async (req, res) => {
  try {
    const token = req.params.token;
    const tenantId = req.params.tenantId;

    console.log("Received Token:", token); // Log the token
    console.log("Received Tenant ID:", tenantId); // Log the tenant ID
    console.log("X-Tenant-Id Header:", req.headers["x-tenant-id"]); // Log the tenant ID header

    // Check if x-tenant-id header is missing
    if (!req.headers["x-tenant-id"]) {
      console.error("Missing x-tenant-id header.");
      return res.status(400).json({ error: "Missing x-tenant-id header." });
    }

    // Ensure the tenant ID in the header matches the one in the URL
    if (req.headers["x-tenant-id"] !== tenantId) {
      console.error("Mismatch between tenant ID in URL and header.");
      return res.status(400).json({ error: "Invalid tenant ID." });
    }

    // Find user by verification token and tenant ID
    const user = await User.findOne({
      verificationToken: token,
      tenant: tenantId,
    });

    // Handle case where user is not found or token is expired
    if (!user) {
      console.error("User not found or verification token expired.");
      return res
        .status(400)
        .json({ error: "Invalid or expired verification token." });
    }

    // Update user to mark email as verified
    user.emailVerified = true;
    user.verificationToken = undefined; // Remove the token after successful verification
    await user.save();

    console.log("Email verified successfully for user:", user._id);

    res.status(200).json({ message: "Email verified successfully!" });
  } catch (error) {
    console.error("Error verifying email:", error.message);
    res
      .status(500)
      .json({ error: "Error verifying email", details: error.message });
  }
};

exports.getUserProfile = async (req, res) => {
  try {
    const userId = req.user.userId; // Extracted from authMiddleware
    const tenantId = req.user.tenantId;

    console.log(
      "Fetching user profile for User ID:",
      userId,
      "and Tenant ID:",
      tenantId
    );

    // Fetch the user by ID and tenant
    const user = await User.findOne({ _id: userId, tenant: tenantId });

    if (!user) {
      console.log(
        "User not found with User ID:",
        userId,
        "and Tenant ID:",
        tenantId
      );
      return res.status(404).json({ error: "User not found" });
    }

    console.log("Fetched user profile successfully:", user);

    res.status(200).json({
      username: user.username,
      email: user.email,
      role: user.role,
      // Include any other user fields you want to send to the frontend
    });
  } catch (error) {
    console.error("Error fetching user profile:", error.message);
    console.error("Stack trace:", error.stack);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};

exports.updateUserProfile = async (req, res) => {
  try {
    const updates = req.body;
    if (updates.password) {
      updates.password = await hashPassword(updates.password);
    }

    const user = await User.findByIdAndUpdate(req.user.userId, updates, {
      new: true,
    }).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    logAction(
      "Profile Updated",
      `User ${user.username} updated their profile.`
    );
    res
      .status(200)
      .json({ message: "Profile updated successfully", data: { user } });
  } catch (error) {
    logAction("Error Updating Profile", error.message);
    res
      .status(500)
      .json({ error: "Error updating user profile", details: error.message });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const { tenantId, userId } = req.params;

    if (!tenantId || !userId) {
      return res.status(400).json({ error: "Tenant ID and User ID are required" });
    }

    // Verify if the tenant exists
    const tenant = await Tenant.findById(tenantId);
    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Delete the user
    const result = await User.deleteOne({ _id: userId, tenant: tenantId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "User not found or already deleted" });
    }

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error.message);
    res.status(500).json({ error: "Error deleting user", details: error.message });
  }
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const { tenantId } = req.params;

  console.log("Received password reset request for email:", email);
  console.log("Tenant ID extracted from URL:", tenantId);

  try {
    // Find the user by email and tenantId
    const user = await User.findOne({ email, tenant: tenantId }).populate(
      "tenant"
    );

    if (!user) {
      console.log(
        "User not found with email:",
        email,
        "and tenant ID:",
        tenantId
      );
      return res.status(404).json({ error: "User not found." });
    }

    console.log("Found user for password reset:", user);

    // Generate a reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    console.log("Generated reset token:", resetToken);

    // Hash the reset token and set the expiration time (e.g., 1 hour)
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    console.log("Hashed reset token:", hashedToken);

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour from now

    // Save the updated user to the database
    await user.save();
    console.log("User updated with reset token and expiry.");

    // Use the tenant's domain directly for the reset URL
    const resetUrl = `${user.tenant.domain}/user/reset-password?token=${resetToken}&tenantId=${tenantId}`;
    console.log("Generated reset URL:", resetUrl);

    // Email subject and message
    const subject = "Password Reset Request";
    const message = `You requested a password reset. Click the following link to reset your password: ${resetUrl} \n\nIf you did not request this, please ignore this email.`;

    // Log email details before sending
    console.log("Preparing to send email with the following details:");
    console.log("To:", user.email);
    console.log("From:", user.tenant.verifiedSenderEmail);
    console.log("Subject:", subject);
    console.log("Message:", message);

    // Send the email
    await sendEmail(
      user.email,
      user.tenant.verifiedSenderEmail,
      subject,
      message,
      user.tenant.sendGridApiKey
    );

    console.log("Password reset email sent successfully.");
    res
      .status(200)
      .json({ message: "Password reset email sent successfully." });
  } catch (error) {
    console.error("Error during forgot password:", error.message);

    // Additional error details if available
    if (error.response) {
      console.error("Error response details:", error.response.body);
    }

    res.status(500).json({ error: "Server error." });
  }
};

// Reset Password - Verify Token and Set New Password
exports.resetPassword = async (req, res) => {
  const { token } = req.params; // Token passed via URL
  const { password } = req.body; // New password from request body

  // Validate password strength
  if (!password || password.length < 6) {
    return res.status(400).json({
      error: "Password must be at least 6 characters long.",
    });
  }

  try {
    console.log("Received reset password request with token:", token);

    // Hash the provided token for secure lookup in the database
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    console.log("Hashed token for database lookup:", hashedToken);

    // Find the user by matching the hashed token and ensuring the token hasn't expired
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }, // Check that the token is still valid
    });

    // If no user found or token expired/invalid, return error
    if (!user) {
      console.log("Invalid or expired reset token:", token);
      return res.status(400).json({
        error: "Invalid or expired token.",
      });
    }

    console.log("User found for password reset:", user.email);

    user.password = password
    
    // Clear the reset token and expiration fields after successful password reset
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    // Save the updated user record in the database password is hashed upon saving
    await user.save();
    console.log("Password reset successful for user:", user.email);

    // Optionally, notify the user via email that their password was changed (code for this is not shown)

    // Return success response to the client
    return res.status(200).json({
      message: "Password has been reset successfully.",
    });
  } catch (error) {
    console.error("Error during password reset:", error.message);

    // Handle unexpected errors gracefully
    return res.status(500).json({
      error: "Server error during password reset.",
    });
  }
};

exports.logoutUser = (req, res) => {
  try {
    // Log the entire request headers for debugging
    console.log("Request Headers:", req.headers);

    // Extract the Authorization header
    const token = req.header("Authorization");
    console.log("Authorization Header:", token);

    // Check if the token is present
    if (!token) {
      console.error("No token provided");
      return res.status(401).json({ error: "No token provided" });
    }

    // Extract the token from the "Bearer " prefix
    const extractedToken = token.replace("Bearer ", "");
    console.log("Extracted Token:", extractedToken);

    // Verify the token
    jwt.verify(extractedToken, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error("JWT Verification Error:", err.message);
        return res
          .status(401)
          .json({ error: "Invalid token", details: err.message });
      }

      console.log("Verified Decoded Token:", decoded);
      res.status(200).json({ message: "User logged out successfully" });
    });
  } catch (error) {
    console.error("Error logging out:", error.message);
    return res
      .status(500)
      .json({ error: "Server error", details: error.message });
  }
};

exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // Log the request body
    console.log("Request body:", req.body);

    // Validate that both oldPassword and newPassword are provided
    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .json({ error: "Both old and new passwords are required" });
    }

    // Ensure user is properly fetched before proceeding
    const user = await User.findById(req.user.userId); // Fetch the user based on the authenticated user ID

    // Log fetched user
    console.log("Fetched user for password change:", user);

    // If user is not found, return an error
    if (!user) {
      console.log("User not found for password change:", req.user.userId);
      return res.status(404).json({ error: "User not found" });
    }

    // Log hashed password from the database
    console.log("Hashed password from DB:", user.password);

    // Compare the old password with the user's current password
    const isMatch = await user.comparePassword(oldPassword);
    console.log("Password match result:", isMatch); // Log the result of the password comparison

    if (!isMatch) {
      console.log("Incorrect old password attempt for user:", user.username);
      return res.status(400).json({ error: "Old password is incorrect" });
    }

    // If old password matches, hash the new password
    user.password = newPassword // Hash the new password

    // Save the updated user details
    await user.save();

    console.log("Password changed successfully for user:", user.username);

    // Send success response
    return res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Error changing password:", error.message);
    return res
      .status(500)
      .json({ error: "Error changing password", details: error.message });
  }
};

exports.getAllUsers = async (req, res) => {
  try {
    // Check if the tenant exists
    if (!req.tenant) {
      return res.status(400).json({ error: "Tenant not found" });
    }

    console.log("Fetching users for tenant ID:", req.tenant._id);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const users = await User.find({ tenant: req.tenant._id })
      .select("-password") // Exclude password from results
      .skip((page - 1) * limit)
      .limit(limit);

    const totalCount = await User.countDocuments({ tenant: req.tenant._id });

    logAction(
      "Users Retrieved",
      `Tenant ID: ${req.tenant._id}, Users Count: ${users.length}`
    );

    res.status(200).json({
      message: "Users retrieved successfully",
      data: { users, totalCount, page, limit },
    });
  } catch (error) {
    logAction("Error Fetching Users", error.message);
    res
      .status(500)
      .json({ error: "Error fetching users", details: error.message });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const { id } = req.params;

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    // Log the incoming request
    console.log(
      `Fetching user with ID: ${id} for tenant ID: ${req.tenant._id}`
    );

    const user = await User.findOne({ _id: id, tenant: req.tenant._id }).select(
      "-password"
    );

    if (!user) {
      logAction("User Not Found", `User ID: ${id}`);
      return res.status(404).json({ error: "User not found" });
    }

    logAction("User Retrieved", `User ID: ${user._id}`);
    res
      .status(200)
      .json({ message: "User retrieved successfully", data: { user } });
  } catch (error) {
    logAction("Error Fetching User", error.message);
    res
      .status(500)
      .json({ error: "Error fetching user", details: error.message });
  }
};

exports.updateUser = async (req, res) => {
  try {
    const { id } = req.params;

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    // Log the incoming request
    console.log(
      `Updating user with ID: ${id} for tenant ID: ${req.tenant._id}`
    );

    const updates = req.body;

    // Hash password if it's being updated
    if (updates.password) {
      updates.password = await bcrypt.hash(sanitize(updates.password), 10);
    }

    // Update the user
    const user = await User.findOneAndUpdate(
      { _id: id, tenant: req.tenant._id },
      updates,
      {
        new: true,
        runValidators: true, // Ensure that validators are run on the update
      }
    ).select("-password");

    if (!user) {
      logAction("Update Attempt for Non-existent User", `User ID: ${id}`);
      return res.status(404).json({ error: "User not found" });
    }

    logAction("User Updated", `User ${user.username} updated their profile.`);
    res
      .status(200)
      .json({ message: "User updated successfully", data: { user } });
  } catch (error) {
    logAction("Error Updating User", error.message);
    res
      .status(500)
      .json({ error: "Error updating user", details: error.message });
  }
};

exports.updateUserRole = async (req, res) => {
  try {
    const { tenantId, userId } = req.params; // Extract tenantId and userId

    // Log the incoming request
    console.log("Incoming request params:", req.params);
    console.log(`User ID to be validated: ${userId}`);

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    // Sanitize and extract role
    const role = sanitize(req.body.role);

    const validRoles = [
      "Admin",
      "Editor",
      "Viewer",
      "SuperAdmin",
      "Guest",
      "Tenant",
    ];
    if (!validRoles.includes(role)) {
      logAction(
        "Invalid Role Update Attempt",
        `User ID: ${userId}, Role: ${role}`
      );
      return res.status(400).json({ error: "Invalid role" });
    }

    console.log(`Updating role for user ID: ${userId} to ${role}`);

    const user = await User.findOneAndUpdate(
      { _id: userId, tenant: req.tenant._id }, // Use userId here
      { role },
      { new: true }
    );

    if (!user) {
      logAction(
        "Role Update Attempt for Non-existent User",
        `User ID: ${userId}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    logAction(
      "User Role Updated",
      `User ${user.username} role updated to ${role}.`
    );
    res.status(200).json({ message: "User role updated successfully", user });
  } catch (error) {
    logAction("Error Updating User Role", error.message);
    res
      .status(500)
      .json({ error: "Error updating user role", details: error.message });
  }
};

exports.activateUser = async (req, res) => {
  try {
    const { userId } = req.params; // Access userId from params

    // Log the incoming request
    console.log("Incoming request params:", req.params);
    console.log(`Activating user with ID: ${userId}`);

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    const user = await User.findOneAndUpdate(
      { _id: userId, tenant: req.tenant._id },
      { status: "Active" },
      { new: true }
    );

    if (!user) {
      logAction(
        "Activation Attempt for Non-existent User",
        `User ID: ${userId}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    logAction("User Activated", `User ${user.username} activated.`);
    res.status(200).json({ message: "User activated successfully", user });
  } catch (error) {
    logAction("Error Activating User", error.message);
    res
      .status(500)
      .json({ error: "Error activating user", details: error.message });
  }
};

exports.deactivateUser = async (req, res) => {
  try {
    const { userId } = req.params;

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    console.log(`Deactivating user with ID: ${userId}`);

    const user = await User.findOneAndUpdate(
      { _id: userId, tenant: req.tenant._id },
      { status: "Inactive" },
      { new: true }
    );

    if (!user) {
      logAction(
        "Deactivation Attempt for Non-existent User",
        `User ID: ${userId}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    logAction("User Deactivated", `User ${user.username} deactivated.`);
    res.status(200).json({ message: "User deactivated successfully", user });
  } catch (error) {
    logAction("Error Deactivating User", error.message);
    res
      .status(500)
      .json({ error: "Error deactivating user", details: error.message });
  }
};

exports.suspendUser = async (req, res) => {
  try {
    const { userId } = req.params;

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID format" });
    }

    console.log(`Suspending user with ID: ${userId}`);

    const user = await User.findOneAndUpdate(
      { _id: userId, tenant: req.tenant._id },
      { status: "Suspended" },
      { new: true }
    );

    if (!user) {
      logAction(
        "Suspension Attempt for Non-existent User",
        `User ID: ${userId}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    logAction("User Suspended", `User ${user.username} suspended.`);
    res.status(200).json({ message: "User suspended successfully", user });
  } catch (error) {
    logAction("Error Suspending User", error.message);
    res
      .status(500)
      .json({ error: "Error suspending user", details: error.message });
  }
};

exports.refreshToken = async (req, res) => {
  try {
    const authHeader = req.header("Authorization"); // Expecting the refresh token in the Authorization header

    // Validate that the Authorization header is provided
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(400).json({ error: "Token is required" });
    }

    const token = authHeader.split(" ")[1]; // Extract the token from the header

    // Decode the token without verifying expiration
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET, {
        ignoreExpiration: true,
      });
    } catch (error) {
      return res.status(401).json({ error: "Invalid token" });
    }

    // Log the decoded payload for debugging
    console.log("Decoded JWT payload:", decoded);

    // Check if the token has expired
    if (decoded.exp && Date.now() >= decoded.exp * 1000) {
      return res.status(401).json({ error: "Token has expired" });
    }

    // Create a new access token
    const newToken = jwt.sign(
      { _id: decoded._id, role: decoded.role },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    logAction("Token Refreshed", `Token refreshed for user ${decoded._id}`);
    res.status(200).json({ token: newToken });
  } catch (error) {
    logAction("Error Refreshing Token", error.message);
    res
      .status(500)
      .json({ error: "Error refreshing token", details: error.message });
  }
};

exports.resendVerificationEmail = async (req, res) => {
  console.log("Incoming request params:", req.params);
  console.log("Request body:", req.body);

  try {
    // Validate input
    if (!req.body.email) {
      return res.status(400).json({ error: "Email is required" });
    }

    // Extract the Authorization header
    const authorization = req.header("Authorization");
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authorization.split(" ")[1]; // Extract the token
    let decoded;

    // Verify the token and extract user ID
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ error: "Invalid token" });
    }

    const userId = decoded._id; // Extract user ID from decoded token

    // Validate email format
    if (!validator.isEmail(req.body.email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    // Look up the user based on email and tenant
    const user = await User.findOne({
      email: req.body.email,
      tenant: req.tenant._id,
    });

    if (!user) {
      logAction(
        "Resend Verification Attempt for Non-existent User",
        `Email: ${req.body.email}, User ID: ${userId}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    if (user.emailVerified) {
      logAction(
        "Resend Verification Attempt for Already Verified Email",
        `Email: ${req.body.email}, User ID: ${userId}`
      );
      return res.status(400).json({ error: "Email already verified" });
    }

    // Generate a new verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");
    user.verificationToken = verificationToken;
    await user.save();

    // Fetch the tenant information
    const tenant = await Tenant.findById(req.tenant._id);
    console.log("Tenant Information:", tenant);

    // Create the verification URL
    const verificationUrl = `${tenant.domain}/verify?token=${verificationToken}&tenantId=${tenant._id}`;

    // Ensure verifiedSenderEmail is populated
    const senderEmail = tenant.verifiedSenderEmail;
    if (!senderEmail) {
      logAction(
        "Error Sending Verification Email",
        "Verified sender email is undefined."
      );
      return res.status(500).json({ error: "Sender email is not defined." });
    }

    // Handle email sending errors
    try {
      await sendEmail(
        user.email,
        senderEmail, // Use the verified sender email
        "Email Verification",
        `Please verify your email by clicking on the following link:\n\n${verificationUrl}`,
        tenant.sendGridApiKey // Ensure this is a valid SendGrid API key
      );
    } catch (emailError) {
      logAction("Error Sending Verification Email", emailError.message);
      return res
        .status(500)
        .json({ error: "Error sending verification email" });
    }

    logAction(
      "Verification Email Resent",
      `Verification email resent to ${req.body.email}, User ID: ${userId}`
    );
    res.status(200).json({ message: "Verification email resent successfully" });
  } catch (error) {
    logAction("Error Resending Verification Email", error.message);
    res.status(500).json({
      error: "Error resending verification email",
      details: error.message,
    });
  }
};

exports.updateUserTenant = async (req, res) => {
  try {
    const { tenantId } = req.body; // New tenant ID provided in the request
    const userId = req.user._id; // Assuming user is authenticated
  
    // Find the new tenant by ID
    const newTenant = await Tenant.findById(tenantId);
    if (!newTenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Update the user's tenant
    const user = await User.findByIdAndUpdate(
      userId,
      { tenant: newTenant._id },
      { new: true }
    ).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    logAction(
      "User Tenant Updated",
      `User ${user.username} changed tenant to ${newTenant.name}.`
    );
    res
      .status(200)
      .json({ message: "User tenant updated successfully", data: { user } });
  } catch (error) {
    logAction("Error Updating User Tenant", error.message);
    res
      .status(500)
      .json({ error: "Error updating user tenant", details: error.message });
  }
};



exports.uploadProfilePicture = (req, res) => {
  const file = req.file;

  if (!file) {
    logAction("Upload Attempt with No File", `User ID: ${req.user._id}`);
    return res.status(400).json({ error: "No file uploaded" });
  }

  const fileName = `${req.user._id}-${Date.now()}${path.extname(
    file.originalname
  )}`;
  const params = {
    Bucket: process.env.DO_SPACES_BUCKET,
    Key: `profile-pictures/${fileName}`,
    Body: file.buffer,
    ACL: "public-read",
    ContentType: file.mimetype,
  };

  s3.upload(params, async (err, data) => {
    if (err) {
      logAction("Error Uploading Profile Picture", err.message);
      return res
        .status(500)
        .json({ error: "Error uploading file", details: err.message });
    }

    try {
      req.user.profilePicture = data.Location;
      await req.user.save();
      logAction(
        "Profile Picture Uploaded",
        `User ${req.user.username} uploaded a new profile picture.`
      );
      res.status(200).json({
        message: "Profile picture uploaded successfully",
        data: { url: data.Location },
      });
    } catch (saveErr) {
      logAction("Error Saving Profile Picture", saveErr.message);
      res
        .status(500)
        .json({
          error: "Error saving user profile picture",
          details: saveErr.message,
        });
    }
  });
};

exports.generateApiKeyForUser = async (req, res) => {
  try {
    const { userId } = sanitize(req.params);
    const user = await User.findById(userId);
    if (!user) {
      logAction(
        "API Key Generation Attempt for Non-existent User",
        `User ID: ${userId}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    const { key } = await generateApiKey(user._id);
    logAction(
      "API Key Generated",
      `API key generated for user ${user.username}.`
    );
    res.status(201).json({
      message: "API key generated successfully",
      data: { apiKey: key },
    });
  } catch (error) {
    logAction("Error Generating API Key", error.message);
    res
      .status(500)
      .json({ error: "Error generating API key", details: error.message });
  }
};