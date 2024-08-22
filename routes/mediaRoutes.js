// routes/mediaRoutes.js
const express = require("express");
const router = express.Router();
const mediaController = require("../controllers/mediaController");
const authMiddleware = require("../middleware/authMiddleware");
const upload = require("../middleware/uploadMiddleware"); // Import the correct upload middleware

// Protected routes (Admin and Tenant)
router.post(
  "/upload",
  authMiddleware.verifyRole(["Admin", "Tenant", "Viewer", "Editor", "SuperAdmin"]),
  upload, // Apply the Multer middleware here for handling file uploads
  mediaController.uploadMedia
);

router.get(
  "/",
  authMiddleware.verifyRole(["Admin", "Tenant", "Viewer", "Editor", "SuperAdmin"]),
  mediaController.getAllMedia
); // Get all media
router.get(
  "/:id",
  authMiddleware.verifyRole(["Admin", "Tenant", "Viewer", "Editor", "SuperAdmin"]),
  mediaController.getMediaById
); // Get media by ID
router.delete(
  "/:id",
  authMiddleware.verifyRole(["Admin", "Tenant", "Viewer", "Editor", "SuperAdmin"]),
  mediaController.deleteMedia
); // Delete media

module.exports = router;
