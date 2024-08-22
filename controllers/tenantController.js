const Tenant = require("../models/Tenant");
const crypto = require("crypto");
const { validationResult } = require("express-validator");
const { logAction } = require("../utils/logger");
const { encrypt } = require("../config/config");
// Create a new tenant
exports.createTenant = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { name, contactEmail, sendGridApiKey, verifiedSenderEmail } =
      req.body;

    // Generate a unique API key for the tenant
    const apiKey = crypto.randomBytes(32).toString("hex");

    // Encrypt the SendGrid API key before storing
    const encryptedSendGridApiKey = encrypt(sendGridApiKey);

    // Create and save the new tenant
    const tenant = new Tenant({
      name,
      contactEmail,
      apiKey,
      sendGridApiKey: encryptedSendGridApiKey,
      verifiedSenderEmail,
    });

    await tenant.save();

    logAction("Tenant Created", `Tenant ID: ${tenant._id}`);
    res.status(201).json({ tenant, apiKey });
  } catch (error) {
    logAction("Error Creating Tenant", error.message);
    if (error.code === 11000) {
      return res.status(400).json({
        error: "Duplicate entry. Please ensure all fields are unique.",
      });
    }
    res.status(500).json({ error: "Server error" });
  }
};

// Get all tenants
exports.getAllTenants = async (req, res) => {
  try {
    const tenants = await Tenant.find();
    res.status(200).json(tenants);
  } catch (error) {
    logAction("Error Fetching Tenants", error.message);
    res.status(500).json({ error: "Server error" });
  }
};

// Get a specific tenant by ID
exports.getTenantById = async (req, res) => {
  try {
    const tenant = await Tenant.findById(req.params.id);

    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    res.status(200).json(tenant);
  } catch (error) {
    logAction("Error Fetching Tenant", error.message);
    res.status(500).json({ error: "Server error" });
  }
};

// Update a tenant
exports.updateTenant = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const updates = req.body;
    const tenant = await Tenant.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true,
    });

    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    res.status(200).json(tenant);
  } catch (error) {
    logAction("Error Updating Tenant", error.message);
    res.status(500).json({ error: "Server error" });
  }
};

// Delete a tenant
exports.deleteTenant = async (req, res) => {
  try {
    const tenant = await Tenant.findByIdAndDelete(req.params.id);

    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    res.status(200).json({ message: "Tenant deleted successfully" });
  } catch (error) {
    logAction("Error Deleting Tenant", error.message);
    res.status(500).json({ error: "Server error" });
  }
};
