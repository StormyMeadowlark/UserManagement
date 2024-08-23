const Tenant = require("../models/Tenant");

const tenantMiddleware = async (req, res, next) => {
  const domain = req.headers.host.split(":")[0]; // Extract the domain from the request

  try {
    // Find the tenant associated with the domain
    const tenant = await Tenant.findOne({ domain });

    if (!tenant) {
      return res.status(404).json({ message: "Tenant not found." });
    }

    req.tenant = tenant; // Attach tenant information to the request
    next();
  } catch (error) {
    console.error("Error fetching tenant information:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
};

module.exports = tenantMiddleware;
