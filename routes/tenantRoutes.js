const express = require("express");
const router = express.Router();
const tenantController = require("../controllers/tenantController");
const authMiddleware = require("../middleware/authMiddleware");

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

module.exports = router;
