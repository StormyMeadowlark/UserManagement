const express = require("express");
const router = express.Router();
const tenantController = require("../controllers/tenantController");
const authMiddleware = require("../middleware/authMiddleware");
const attachTenant = require("../middleware/attachTenant");

// Require dotenv to load environment variables
const dotenv = require("dotenv");
dotenv.config(); // This will load the environment variables from your .env file
// Tenant creation - SuperAdmin only
router.get("/verify-tenant", tenantController.verifyTenant);

router.post(
  "/",
  authMiddleware.verifyRole(["SuperAdmin"]), // Ensure the user is a SuperAdmin
  (req, res, next) => {
    const superAdminEmail = process.env.SUPERADMIN_EMAIL; // Your specific SuperAdmin email

    // Check if the logged-in user's email matches the SuperAdmin email
    if (req.user.email !== superAdminEmail) {
      return res.status(403).json({
        error: "Access denied. Only the SuperAdmin can create tenants.",
      });
    }

    next(); // Proceed to the tenantController.createTenant if authorized
  },
  tenantController.createTenant
);

router.get(
  "/",
  attachTenant,
  (req, res, next) => {
    const superAdminEmail = process.env.SUPERADMIN_EMAIL; // Your specific SuperAdmin email

    // Check if the logged-in user's email matches the SuperAdmin email
    if (req.user.email !== superAdminEmail) {
      return res.status(403).json({
        error: "Access denied. Only the SuperAdmin can create tenants.",
      });
    }

    next(); // Proceed to the tenantController.createTenant if authorized
  },
  authMiddleware.verifyRole(["SuperAdmin"]),
  tenantController.getAllTenants
);



router.get(
  "/:id",
  attachTenant,
  tenantController.getTenantById
);



router.put(
  "/:id",
  attachTenant,
  authMiddleware.verifyRole(["SuperAdmin"]),
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
