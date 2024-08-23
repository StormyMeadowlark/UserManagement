const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const authMiddleware = require("../middleware/authMiddleware");
const uploadProfilePictureMiddleware = require("../middleware/uploadMiddleware");
const verifyApiKey  = require("../middleware/verifyApiKey");
const checkBlacklist = require("../middleware/checkBlacklist");
const attachTenant = require("../utils/attachTenant")


// Public routes
router.post("/register", userController.registerUser); // Register a new user tested
router.post("/login", userController.loginUser); // Login a user tested
router.get("/verify-email/:token", userController.verifyEmail); // Email verification tested

// Protected routes for logged-in users (with roles)
router.get(
  "/profile",
  authMiddleware.verifyUser,
  userController.getUserProfile
); // Get the logged-in user's profile tested

router.put(
  "/profile",
  authMiddleware.verifyUser,
  userController.updateUserProfile
); // Update logged-in user's profile testede

router.post(
  "/change-password",
  authMiddleware.verifyUser,
  userController.changePassword
); // Change password for logged-in user

// Password reset routes
router.post("/forgot-password", userController.forgotPassword); // Request password reset
router.post("/reset-password", userController.resetPassword); // Reset password

router.post(
  "/logout",
  authMiddleware.verifyUser,
  userController.logoutUser
); // Logout user tested

// Admin/SuperAdmin routes
router.get(
  "/",
attachTenant,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.getAllUsers
); // Get all users

router.get(
  "/:id",
  attachTenant,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  checkBlacklist,
  userController.getUserById
); // Get user by ID

router.put(
  "/:id",
  attachTenant,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  checkBlacklist,
  userController.updateUser
); // Update user details

router.delete(
  "/:id",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  checkBlacklist,
  userController.deleteUser
); // Delete a user (SuperAdmin only)

router.post(
  "/generate-api-key/:userId",
  attachTenant,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.generateApiKeyForUser
); // Generate API key for user

router.post(
  "/upload-profile-picture",
  attachTenant,
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
  attachTenant,
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.searchUsers
); // Search users

router.put(
  "/users/:id/deactivate",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  userController.deactivateUser
); // Deactivate user

router.post("/refresh-token", userController.refreshToken); // Refresh JWT token

router.put(
  "/users/:id/activate",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  userController.activateUser
); // Activate user

router.put(
  "/users/:id/role",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  userController.updateUserRole
); // Update user role

router.get("/roles", userController.getRoles); // Get available roles

router.put(
  "/users/update-tenant",
  attachTenant,
  authMiddleware.verifyRole([
    "Admin",
    "Editor",
    "Viewer",
    "SuperAdmin",
    "Tenant",
  ]), // Ensure the user is authenticated
  userController.updateUserTenant // Call the updateUserTenant function
);

module.exports = router;
