
const { logAction } = require("../utils/logger");
const sanitize = require("sanitize-html");

const bcrypt = require("bcrypt");
const Tenant = require("../models/Tenant"); // Adjust the path to your Tenant model if necessary

const tenantMiddleware = async (req, res, next) => {
  try {
    const apiKey = req.headers["x-api-key"]; // Assuming the API key is passed in the request headers
    if (!apiKey) {
      return res.status(400).json({ error: "API key is required" });
    }

    const tenant = await Tenant.findOne({ apiKey }); // Fetch the tenant using the API key
    if (!tenant || !tenant.hashedApiKey) {
      return res
        .status(404)
        .json({ error: "Tenant not found or invalid hashed API key" });
    }

    console.log("API Key:", apiKey);
    console.log("Hashed API Key:", tenant.ApiKey);

    const isValid = await bcrypt.compare(apiKey, tenant.ApiKey); // Compare the API key with the hashed version
    if (!isValid) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    next();
  } catch (error) {
    console.error("Error verifying tenant:", error);
    return res
      .status(500)
      .json({ error: "Server error", details: error.message });
  }
};

module.exports = tenantMiddleware;

