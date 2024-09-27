const express = require("express");
const router = express.Router();
const organizationController = require("../controllers/organizationController"); // Ensure this path is correct

// Create a new organization
router.post(
  "/:tenantId/",
  organizationController.createOrganization
);

// Get all organizations for a tenant
router.get("/:tenantId/organizations", organizationController.getOrganizations); // Corrected to match the controller method

// Get an organization by ID
router.get(
  "/:tenantId/:id",
  organizationController.getOrganizationById
);

// Update an organization
router.put(
  "/:tenantId/:id",
  organizationController.updateOrganization
);

// Delete an organization
router.delete(
  "/:tenantId/:id",
  organizationController.deleteOrganization
);

module.exports = router;
