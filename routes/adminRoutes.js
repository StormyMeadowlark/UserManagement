const express = require("express");
const router = express.Router();
const adminController = require("../controllers/adminController");
const settingsController = require("../controllers/settingsController");
const authMiddleware = require("../middleware/authMiddleware");
 // Assuming you have this

// Admin Dashboard - Tenant-specific
router.get(
  "/dashboard",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
 // Ensure tenant context is available
  adminController.getDashboardData
); // Get data for admin dashboard

// Settings Management (Admin-only) - Tenant-specific
router.get(
  "/settings",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
 // Ensure tenant context is available
  settingsController.getSettings
); // Get all settings

router.put(
  "/settings",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
// Ensure tenant context is available
  settingsController.updateSettings
); // Update settings

module.exports = router;
