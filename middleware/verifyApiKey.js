const Tenant = require("../models/Tenant");
const User = require("../models/User");

const verifyApiKey = async (req, res, next) => {
  try {
    const apiKey = req.header("x-api-key");
    if (!apiKey) {
      return res.status(401).json({ error: "API key is required" });
    }

    const tenant = await Tenant.findOne({ apiKey });
    if (!tenant) {
      return res.status(403).json({ error: "Invalid API key" });
    }

    req.tenant = tenant;

    // Optionally, check if the user is associated with this tenant
    const userId = req.user._id;
    const user = await User.findOne({ _id: userId, tenant: tenant._id });

    if (!user) {
      return res
        .status(403)
        .json({ error: "User not authorized for this tenant" });
    }

    next();
  } catch (error) {
    console.error("Error verifying API key:", error);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};

module.exports = verifyApiKey;
