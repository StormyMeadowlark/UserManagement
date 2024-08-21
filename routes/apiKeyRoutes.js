const express = require("express");
const router = express.Router();
const apiKeyController = require("../controllers/apiKeyController");
const authMiddleware = require("../middleware/authMiddleware");
const tenantMiddleware = require("../middleware/tenantMiddleware");

// Route to generate an API key for a specific tenant
router.post(
  "/generate-api-key",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  tenantMiddleware, // Ensure tenant context is available
  apiKeyController.generateApiKey
);

// Route to revoke an API key for a specific tenant
router.delete(
  "/revoke-api-key/:key",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  tenantMiddleware, // Ensure tenant context is available
  apiKeyController.revokeApiKey
);

module.exports = router;
