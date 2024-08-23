const express = require("express");
const router = express.Router();
const tenantController = require("../controllers/tenantController");
const authMiddleware = require("../middleware/authMiddleware");
const tenantMiddleware = require("../middleware/tenantMiddleware")
const attachTenant = require("../utils/attachTenant");

router.post(
  "/",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.createTenant
);
router.get(
  "/",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.getAllTenants
);
router.get(
  "/:id",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.getTenantById
);
router.put(
  "/:id",
  attachTenant,
  authMiddleware.verifyRole(["Admin", "Editor", "Viewer"]),
  tenantController.updateTenant
);
router.delete(
  "/:id",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.deleteTenant
);
router.post(
  "/regenerate-api-key/:tenantId",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.regenerateApiKey
);
module.exports = router;
