const express = require("express");
const router = express.Router();
const apiKeyController = require("../controllers/apiKeyController");
const authMiddleware = require("../middleware/authMiddleware");

router.post(
  "/generate-api-key",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
 // Ensure tenant context is available
  apiKeyController.generateApiKey
);

router.delete(
  "/revoke-api-key/:key",
  authMiddleware.verifyRole(["Admin", "SuperAdmin"]),
// Ensure tenant context is available
  apiKeyController.revokeApiKey
);

module.exports = router;
