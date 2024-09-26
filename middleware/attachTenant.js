const mongoose = require("mongoose");
const Tenant = require("../models/Tenant"); // Adjust the path as needed

module.exports = async (req, res, next) => {
  const tenantId = req.headers["x-tenant-id"];

  // Check if the X-Tenant-Id header is provided
  if (!tenantId) {
    console.error("[Tenant Middleware] X-Tenant-Id header is missing.");
    return res.status(400).json({ message: "X-Tenant-Id header is required" });
  }

  // Validate tenantId format (assuming MongoDB ObjectId)
  if (!mongoose.Types.ObjectId.isValid(tenantId)) {
    console.error("[Tenant Middleware] Invalid tenant ID format.");
    return res.status(400).json({ message: "Invalid X-Tenant-Id format" });
  }

  console.log(`[Tenant Middleware] Tenant ID received: ${tenantId}`);

  try {
    // Fetch tenant from the database
    const tenant = await Tenant.findById(tenantId);

    if (!tenant) {
      console.error("[Tenant Middleware] Tenant not found.");
      return res.status(404).json({ message: "Tenant not found" });
    }

    // Attach the tenant to the request object
    req.tenant = tenant; // You can access this in your routes
    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    console.error("[Tenant Middleware] Error fetching tenant:", error.message);
    return res.status(500).json({ message: "Internal server error" });
  }
};
