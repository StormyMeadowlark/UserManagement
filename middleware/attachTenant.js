const mongoose = require("mongoose"); // Optional: for ObjectId validation

module.exports = (req, res, next) => {
  const tenantId = req.headers["x-tenant-id"];

  // Check if the X-Tenant-Id header is provided
  if (!tenantId) {
    console.error("[Tenant Middleware] X-Tenant-Id header is missing.");
    return res.status(400).json({ message: "X-Tenant-Id header is required" });
  }

  // Optional: Validate tenantId format (assuming MongoDB ObjectId)
  if (!mongoose.Types.ObjectId.isValid(tenantId)) {
    console.error("[Tenant Middleware] Invalid tenant ID format.");
    return res.status(400).json({ message: "Invalid X-Tenant-Id format" });
  }

  console.log(`[Tenant Middleware] Tenant ID received: ${tenantId}`);

  req.tenantId = tenantId;
  next();
};
