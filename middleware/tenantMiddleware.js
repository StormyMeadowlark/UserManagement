const Tenant = require("../models/Tenant");
const { logAction } = require("../utils/logger");
const sanitize = require("sanitize-html");

const tenantMiddleware = async (req, res, next) => {
  try {
    // Extract and sanitize the API key from the headers
    const apiKey = sanitize(req.headers["x-api-key"]);

    if (!apiKey) {
      logAction("No API Key Provided", "x-api-key header missing");
      return res.status(403).json({ error: "No API key provided" });
    }

    // Find the tenant associated with the API key
    const tenant = await Tenant.findOne({ apiKey });

    if (!tenant) {
      logAction("Invalid API Key", `No tenant found for API key: ${apiKey}`);
      return res.status(403).json({ error: "Invalid API key" });
    }

    // Attach the tenant to the request object for further use
    req.tenant = tenant;
    logAction("Tenant Verified", `Tenant ${tenant.name} verified with API key`);
    next();
  } catch (error) {
    logAction("Error Verifying Tenant", error.message);
    console.error("Error verifying tenant:", error);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};

module.exports = tenantMiddleware;
