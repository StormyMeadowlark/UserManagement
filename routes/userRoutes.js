const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const authMiddleware = require("../middleware/authMiddleware");
const attachTenant = require("../middleware/attachTenant");

// Apply tenant middleware to routes requiring tenant ID
router.use("/:tenantId", attachTenant);

// Public routes
router.post("/:tenantId/register", userController.registerUser);
router.post("/:tenantId/login", userController.loginUser);
router.get("/:tenantId/verify-email/:token", userController.verifyEmail);

// Protected routes
router.get(
  "/:tenantId/profile",
  authMiddleware.verifyUser,
  userController.getUserProfile
);
router.put(
  "/:tenantId/profile",
  authMiddleware.verifyUser,
  userController.updateUserProfile
);
router.post(
  "/:tenantId/change-password",
  authMiddleware.verifyUser,
  userController.changePassword
);
router.post(
  "/:tenantId/resend-verification-email",
  userController.resendVerificationEmail
);
// Password reset routes
router.post("/:tenantId/forgot-password", userController.forgotPassword);
router.post("/:tenantId/reset-password/:token", userController.resetPassword);

// Admin/SuperAdmin routes
router.get(
  "/:tenantId",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.getAllUsers
);
router.get(
  "/:tenantId/:id",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.getUserById
);
router.put(
  "/:tenantId/:id",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.updateUser
);
router.delete("/:tenantId/user/:userId", authMiddleware.verifyRole(["Admin", "SuperAdmin"]), userController.deleteUser);

router.post("/:tenantId/logout", userController.logoutUser)

router.post("/:tenantId/:userId", authMiddleware.verifyRole(["Admin", "SuperAdmin"]), userController.updateUserRole)

router.put("/:tenantId/:userId/activate", authMiddleware.verifyRole(["Admin", "SuperAdmin"]), userController.activateUser)
router.put("/:tenantId/:userId/deactivate", authMiddleware.verifyRole(["Admin", "SuperAdmin"]), userController.deactivateUser);
router.put("/:tenantId/:userId/suspend", authMiddleware.verifyRole(["Admin", "SuperAdmin"]), userController.suspendUser);

router.post(
  "/:tenantId/:userId/refresh-token",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  userController.refreshToken
);



module.exports = router;

