const bcrypt = require("bcrypt");
const Tenant = require("../models/Tenant");
const { logAction } = require("../utils/logger");
const sanitize = require("sanitize-html");

const ApiKey = require("../models/ApiKey");

exports.verifyApiKey = async (req, res, next) => {
  try {
    const apiKey = req.header("x-api-key");

    if (!apiKey) {
      return res.status(401).json({ error: "API key is required" });
    }

    const tenant = await Tenant.findOne({ apiKey: apiKey });

    if (!tenant) {
      return res.status(403).json({ error: "Invalid API key" });
    }

    // Find the corresponding API key record
    const apiKeyRecord = await ApiKey.findOne({ userId: tenant.userId });

    if (!apiKeyRecord || !(await apiKeyRecord.verifyKey(apiKey))) {
      return res.status(403).json({ error: "Invalid API key" });
    }

    req.tenant = tenant; // Attach tenant information to the request object
    next();
  } catch (error) {
    console.error("Error verifying API key:", error);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};

