const express = require("express");
const router = express.Router();
const apiKeyController = require("../controllers/apiKeyController");
const authMiddleware = require("../middleware/authMiddleware");
const tenantMiddleware = require("../middleware/tenantMiddleware");

router.post(
  "/generate-api-key",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  tenantMiddleware, // Ensure tenant context is available
  apiKeyController.generateApiKey
);

router.delete(
  "/revoke-api-key/:key",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
  tenantMiddleware, // Ensure tenant context is available
  apiKeyController.revokeApiKey
);

module.exports = router;
