const Settings = require("../models/Settings");
const { validationResult } = require("express-validator");
const { logAction } = require("../utils/logger");

// Get the current settings for the tenant
exports.getSettings = async (req, res) => {
  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request

    logAction("Fetching Settings", `Tenant ID: ${tenantId}`);

    const settings = await Settings.findOne({ tenant: tenantId }); // Find settings for the specific tenant
    if (!settings) {
      logAction("Settings Not Found", `Tenant ID: ${tenantId}`);
      return res.status(404).json({ error: "Settings not found" });
    }
    res.status(200).json(settings);
  } catch (error) {
    logAction(
      "Error Fetching Settings",
      `Tenant ID: ${req.tenant._id}, Error: ${error.message}`
    );
    res.status(500).json({ error: "Error fetching settings" });
  }
};

// Update the settings for the tenant
exports.updateSettings = async (req, res) => {
  // Validation check
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request

    logAction("Updating Settings", `Tenant ID: ${tenantId}`);

    const updatedSettings = await Settings.findOneAndUpdate(
      { tenant: tenantId }, // Ensure we are updating the settings for the specific tenant
      req.body,
      {
        new: true,
        upsert: true, // Create a new document if none exists
      }
    );

    logAction("Settings Updated", `Tenant ID: ${tenantId}`);
    res.status(200).json(updatedSettings);
  } catch (error) {
    logAction(
      "Error Updating Settings",
      `Tenant ID: ${req.tenant._id}, Error: ${error.message}`
    );
    res.status(500).json({ error: "Error updating settings" });
  }
};
