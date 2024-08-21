const Tenant = require("../models/Tenant");
const crypto = require("crypto"); // Ensure you have this required in your controller
const { validationResult } = require("express-validator");
const { logAction } = require("../utils/logger"); // Assuming you have a logging utility

const { generateApiKey } = require("../utils/apiKeyUtil");

exports.generateApiKey = async (req, res) => {
  try {
    const { userId } = req.body;

    // Generate the API key
    const apiKey = await generateApiKey(userId); // This function should handle hashing internally

    res.status(201).json({ message: "API key generated successfully", apiKey });
  } catch (error) {
    console.error("Error generating API key:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
};


exports.revokeApiKey = async (req, res) => {
  // Validation check
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request

    logAction("Revoking API Key", `Tenant ID: ${tenantId}`);

    const tenant = await Tenant.findByIdAndUpdate(
      tenantId,
      { apiKey: null },
      { new: true }
    );

    if (!tenant) {
      logAction("Tenant Not Found", `Tenant ID: ${tenantId}`);
      return res.status(404).json({ error: "Tenant not found" });
    }

    logAction("API Key Revoked", `Tenant ID: ${tenantId}`);
    res.status(200).json({ message: "API key revoked successfully" });
  } catch (error) {
    logAction(
      "Error Revoking API Key",
      `Tenant ID: ${req.tenant._id}, Error: ${error.message}`
    );
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
};
