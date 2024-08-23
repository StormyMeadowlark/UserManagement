const express = require("express");
const router = express.Router();
const tenantController = require("../controllers/tenantController");
const authMiddleware = require("../middleware/authMiddleware");
const tenantMiddleware = require("../middleware/tenantMiddleware")

router.post(
  "/",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.createTenant
);
router.get(
  "/",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.getAllTenants
);
router.get(
  "/:id",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.getTenantById
);
router.put(
  "/:id",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.updateTenant
);
router.delete(
  "/:id",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.deleteTenant
);
router.post(
  "/regenerate-api-key/:tenantId",
  tenantMiddleware,
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.regenerateApiKey
);
module.exports = router;
