const express = require("express");
const router = express.Router();
const tenantController = require("../controllers/tenantController");
const authMiddleware = require("../middleware/authMiddleware");
const tenantMiddleware = require("../middleware/tenantMiddleware"); // Assuming you have tenant middleware

// Routes for tenant management
router.post(
  "/",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.createTenant
); // Create a new tenant

router.get(
  "/",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.getAllTenants
); // Get all tenants

router.get(
  "/:id",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantMiddleware, // Ensure tenant context is available
  tenantController.getTenantById
); // Get a specific tenant by ID

router.put(
  "/:id",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantMiddleware, // Ensure tenant context is available
  tenantController.updateTenant
); // Update a tenant by ID

router.delete(
  "/:id",
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantMiddleware, // Ensure tenant context is available
  tenantController.deleteTenant
); // Delete a tenant by ID

module.exports = router;
