const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const authMiddleware = require("../middleware/authMiddleware");
const uploadProfilePictureMiddleware = require("../middleware/uploadMiddleware");
const { verifyApiKey } = require("../middleware/verifyApiKey");
const checkBlacklist = require("../middleware/checkBlacklist");

// Public routes
router.post("/register", userController.registerUser); // Register a new user
router.post("/login", userController.loginUser); // Login a user
router.get("/verify-email/:token", userController.verifyEmail); // Email verification

// Protected routes for logged-in users (with roles)
router.get(
  "/profile",
  checkBlacklist,
  authMiddleware.verifyRole([
    "Admin",
    "Editor",
    "Viewer",
    "SuperAdmin",
    "Tenant",
  ]),
  userController.getUserProfile
); // Get the logged-in user's profile

router.put(
  "/profile",
  checkBlacklist,
  authMiddleware.verifyRole([
    "Admin",
    "Editor",
    "Viewer",
    "SuperAdmin",
    "Tenant",
  ]),
  userController.updateUserProfile
); // Update logged-in user's profile

router.post(
  "/change-password",
  checkBlacklist,
  authMiddleware.verifyRole([
    "Admin",
    "Editor",
    "Viewer",
    "SuperAdmin",
    "Tenant",
  ]),
  userController.changePassword
); // Change password for logged-in user

// Password reset routes
router.post("/forgot-password", userController.forgotPassword); // Request password reset
router.post("/reset-password", userController.resetPassword); // Reset password

router.post(
  "/logout",
  authMiddleware.verifyUser,
  checkBlacklist,
  userController.logoutUser
); // Logout user

// Admin/SuperAdmin routes
router.get(
  "/",
  verifyApiKey,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  checkBlacklist,
  userController.getAllUsers
); // Get all users

router.get(
  "/:id",
  verifyApiKey,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  checkBlacklist,
  userController.getUserById
); // Get user by ID

router.put(
  "/:id",
  verifyApiKey,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  checkBlacklist,
  userController.updateUser
); // Update user details

router.delete(
  "/:id",
  verifyApiKey,
  authMiddleware.verifyRole(["SuperAdmin"]),
  checkBlacklist,
  userController.deleteUser
); // Delete a user (SuperAdmin only)

router.post(
  "/:userId/api-key",
  verifyApiKey,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.generateApiKeyForUser
); // Generate API key for user

router.post(
  "/upload-profile-picture",
  verifyApiKey,
  authMiddleware.verifyRole([
    "Admin",
    "Editor",
    "Viewer",
    "SuperAdmin",
    "Tenant",
  ]),
  uploadProfilePictureMiddleware,
  userController.uploadProfilePicture
); // Upload profile picture

router.post("/resend-verification", userController.resendVerificationEmail); // Resend email verification

router.get(
  "/users/search",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.searchUsers
); // Search users

router.put(
  "/users/:id/deactivate",
  authMiddleware.verifyRole(["SuperAdmin"]),
  userController.deactivateUser
); // Deactivate user

router.post("/refresh-token", userController.refreshToken); // Refresh JWT token

router.put(
  "/users/:id/activate",
  authMiddleware.verifyRole(["SuperAdmin"]),
  userController.activateUser
); // Activate user

router.put(
  "/users/:id/role",
  authMiddleware.verifyRole(["SuperAdmin"]),
  userController.updateUserRole
); // Update user role

router.get("/roles", userController.getRoles); // Get available roles

module.exports = router;
