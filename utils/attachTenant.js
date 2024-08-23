const Tenant = require("../models/Tenant"); // Adjust path as necessary

// Middleware to attach tenant information to request
const attachTenant = async (req, res, next) => {
  try {
    // Example: Extract tenant ID from headers, query params, or session
    const tenantId = req.header("X-Tenant-ID") || req.query.tenantId;

    if (!tenantId) {
      return res.status(400).json({ error: "Tenant ID is required" });
    }

    // Fetch tenant from database
    const tenant = await Tenant.findById(tenantId);

    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Attach tenant to request
    req.tenant = tenant;
    next();
  } catch (error) {
    console.error("Error attaching tenant:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

module.exports = attachTenant;
