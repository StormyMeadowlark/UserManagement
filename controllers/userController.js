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
const ApiKey = require("../models/ApiKey");

exports.registerUser = async (req, res) => {
  try {
    const { name, username, email, password, tenant, role } = req.body;

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

    // Generate a verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");

    // Create a new user
    const newUser = new User({
      name,
      username,
      email,
      role,
      password, // Password will be hashed by schema pre-save hook
      tenant: tenantObj._id,
      verificationToken,
    });

    // Save the new user
    await newUser.save();

    // Generate verification URL
    const verificationUrl = `${req.protocol}://${req.get("host")}/api/v1/users/${
      tenant
    }/verify-email/${verificationToken}`;

    // Send verification email
    await sendEmail(
      newUser.email,
      tenantObj.verifiedSenderEmail,
      "Email Verification",
      `Please verify your email by clicking on the following link:\n\n${verificationUrl}`,
      tenantObj.sendGridApiKey
    );

    // Send success response
    res.status(201).json({
      message:
        "User registered successfully. Please check your email to verify your account.",
    });
  } catch (error) {
    console.error("Error registering user:", error.message);
    res.status(500).json({ error: `Error registering user: ${error.message}` });
  }
};

exports.loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;
    const tenantId = req.headers["x-tenant-id"];

    if (!tenantId) {
      return res.status(400).json({ error: "Tenant ID is required" });
    }

    const user = await User.findOne({ username, tenant: tenantId });

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { userId: user._id, tenantId },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ token, message: "Login successful" });
  } catch (error) {
    console.error("Error logging in:", error.message);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};

exports.verifyEmail = async (req, res) => {
  try {
    const token = sanitize(req.params.token); // Sanitize token input
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      logAction("Invalid Verification Token", `Token: ${token}`);
      return res
        .status(400)
        .json({ error: "Invalid or expired verification token." });
    }

    user.emailVerified = true;
    user.verificationToken = undefined; // Remove the token after verification
    await user.save();

    logAction("Email Verified", `User ${user.username} verified their email.`);
    res
      .status(200)
      .json({ message: "Email verified successfully", data: { user } });
  } catch (error) {
    logAction("Error Verifying Email", error.message);
    res
      .status(500)
      .json({ error: "Error verifying email", details: error.message });
  }
};

exports.getUserProfile = async (req, res) => {
  try {
    const userId = req.user.userId;
    const tenantId = req.user.tenantId;

    // Find the user by ID and tenant
    const user = await User.findOne({ _id: userId, tenant: tenantId });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({ user });
  } catch (error) {
    console.error("Error fetching user profile:", error.message);
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
    res
      .status(201)
      .json({
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

exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const sanitizedOldPassword = sanitize(oldPassword);
    const sanitizedNewPassword = sanitize(newPassword);

    const user = await User.findById(req.user._id);

    if (!user) {
      logAction(
        "Password Change Attempt for Non-existent User",
        `User ID: ${req.user._id}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await comparePassword(sanitizedOldPassword, user.password);
    if (!isMatch) {
      logAction("Incorrect Old Password Attempt", `User ID: ${user._id}`);
      return res.status(400).json({ error: "Old password is incorrect" });
    }

    user.password = await hashPassword(sanitizedNewPassword);
    await user.save();
    logAction(
      "Password Changed",
      `User ${user.username} changed their password.`
    );
    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    logAction("Error Changing Password", error.message);
    res
      .status(500)
      .json({ error: "Error changing password", details: error.message });
  }
};

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find({ tenant: req.tenant._id }).select(
      "-password"
    ); // Fetch users only for the tenant
    logAction(
      "Users Retrieved",
      `Tenant ID: ${req.tenant._id}, Users Count: ${users.length}`
    );
    res
      .status(200)
      .json({ message: "Users retrieved successfully", data: { users } });
  } catch (error) {
    logAction("Error Fetching Users", error.message);
    res
      .status(500)
      .json({ error: "Error fetching users", details: error.message });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const { id } = sanitize(req.params);
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
    const { id } = sanitize(req.params);
    const updates = req.body;

    // Hash password if it's being updated
    if (updates.password) {
      updates.password = await hashPassword(sanitize(updates.password));
    }

    // Update the user
    const user = await User.findOneAndUpdate(
      { _id: id, tenant: req.tenant._id },
      updates,
      {
        new: true,
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

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email }).populate("tenant");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/users/reset-password/${resetToken}`;

    // Send password reset email
    await sendEmail(
      user.email,
      user.tenant.verifiedSenderEmail, // Ensure you have this field in the tenant model
      "Password Reset Request",
      `Please click the following link to reset your password:\n\n${resetUrl}`,
      user.tenant.sendGridApiKey // Use the tenant-specific SendGrid API key
    );

    res
      .status(200)
      .json({ message: "Password reset email sent successfully." });
  } catch (error) {
    console.error("Error requesting password reset:", error.message);
    res
      .status(500)
      .json({ error: `Error requesting password reset: ${error.message}` });
  }
};


exports.resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = sanitize(req.body);
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      logAction("Invalid Password Reset Token", `Token: ${resetToken}`);
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    user.password = await hashPassword(sanitize(newPassword));
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    logAction("Password Reset", `User ${user.username} reset their password.`);
    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    logAction("Error Resetting Password", error.message);
    res
      .status(500)
      .json({ error: "Error resetting password", details: error.message });
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



exports.getRoles = (req, res) => {
  const roles = ["Admin", "Editor", "Viewer", "SuperAdmin", "Guest", "Tenant"];
  logAction("Roles Retrieved", `Roles: ${roles.join(", ")}`);
  res.status(200).json({ roles });
};

exports.updateUserRole = async (req, res) => {
  try {
    const { id } = sanitize(req.params);
    const { role } = sanitize(req.body);

    const validRoles = [
      "Admin",
      "Editor",
      "Viewer",
      "SuperAdmin",
      "Guest",
      "Tenant",
    ];
    if (!validRoles.includes(role)) {
      logAction("Invalid Role Update Attempt", `User ID: ${id}, Role: ${role}`);
      return res.status(400).json({ error: "Invalid role" });
    }

    const user = await User.findOneAndUpdate(
      { _id: id, tenant: req.tenant._id },
      { role },
      { new: true }
    );

    if (!user) {
      logAction("Role Update Attempt for Non-existent User", `User ID: ${id}`);
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
    const { id } = sanitize(req.params);

    const user = await User.findOneAndUpdate(
      { _id: id, tenant: req.tenant._id },
      { status: "Active" },
      { new: true }
    );

    if (!user) {
      logAction("Activation Attempt for Non-existent User", `User ID: ${id}`);
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
    const { id } = sanitize(req.params);

    const user = await User.findOneAndUpdate(
      { _id: id, tenant: req.tenant._id },
      { status: "Deactivated" },
      { new: true }
    );

    if (!user) {
      logAction("Deactivation Attempt for Non-existent User", `User ID: ${id}`);
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

exports.refreshToken = async (req, res) => {
  try {
    const { token } = sanitize(req.body);
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      ignoreExpiration: true,
    });

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

exports.searchUsers = async (req, res) => {
  try {
    const { query } = sanitize(req.query);
    const users = await User.find({
      tenant: req.tenant._id,
      $or: [
        { username: { $regex: query, $options: "i" } },
        { email: { $regex: query, $options: "i" } },
      ],
    }).select("-password");

    logAction("User Search", `Search query: ${query}`);
    res.status(200).json({ users });
  } catch (error) {
    logAction("Error Searching Users", error.message);
    res
      .status(500)
      .json({ error: "Error searching users", details: error.message });
  }
};

exports.resendVerificationEmail = async (req, res) => {
  try {
    const { email } = sanitize(req.body);
    const user = await User.findOne({ email, tenant: req.tenant._id });

    if (!user) {
      logAction(
        "Resend Verification Attempt for Non-existent User",
        `Email: ${email}`
      );
      return res.status(404).json({ error: "User not found" });
    }

    if (user.emailVerified) {
      logAction(
        "Resend Verification Attempt for Already Verified Email",
        `Email: ${email}`
      );
      return res.status(400).json({ error: "Email already verified" });
    }

    const verificationToken = crypto.randomBytes(20).toString("hex");
    user.verificationToken = verificationToken;
    await user.save();

    const verificationUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/users/verify-email/${verificationToken}`;
    await sendEmail(
      user.email,
      "Email Verification",
      `Please verify your email by clicking on the following link:\n\n${verificationUrl}`
    );

    logAction(
      "Verification Email Resent",
      `Verification email resent to ${email}`
    );
    res.status(200).json({ message: "Verification email resent successfully" });
  } catch (error) {
    logAction("Error Resending Verification Email", error.message);
    res
      .status(500)
      .json({
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
