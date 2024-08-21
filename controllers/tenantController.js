const crypto = require("crypto");
const Tenant = require("../models/Tenant");
const { validationResult } = require("express-validator");
const { logAction } = require("../utils/logger");
const { encrypt } = require("../utils/encryption");


// Create a new tenant
exports.createTenant = async (req, res) => {
  // Validation check
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { name, contactEmail, services } = req.body;

    logAction("Creating Tenant", `Tenant Name: ${name}`);

    // Check if name and contactEmail are provided
    if (!name || !contactEmail) {
      return res
        .status(400)
        .json({ error: "Name and contact email are required." });
    }

    // Generate a unique API key
    const apiKey = crypto.randomBytes(32).toString("hex");

    const tenant = new Tenant({ name, contactEmail, apiKey, services });
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
    logAction("Fetching All Tenants");

    const tenants = await Tenant.find().populate("users");

    logAction("Tenants Fetched", `Count: ${tenants.length}`);
    res.status(200).json(tenants);
  } catch (error) {
    logAction("Error Fetching Tenants", error.message);
    res.status(500).json({ error: "Server error" });
  }
};

// Get a specific tenant by ID
exports.getTenantById = async (req, res) => {
  try {
    logAction("Fetching Tenant by ID", `Tenant ID: ${req.params.id}`);

    const tenant = await Tenant.findById(req.params.id).populate("users");

    if (!tenant) {
      logAction("Tenant Not Found", `Tenant ID: ${req.params.id}`);
      return res.status(404).json({ error: "Tenant not found" });
    }

    logAction("Tenant Fetched", `Tenant ID: ${req.params.id}`);
    res.status(200).json(tenant);
  } catch (error) {
    logAction("Error Fetching Tenant", error.message);
    res.status(500).json({ error: "Server error" });
  }
};

// Update a tenant
exports.updateTenant = async (req, res) => {
  // Validation check
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    logAction("Updating Tenant", `Tenant ID: ${req.params.id}`);

    const updates = req.body;

    // Encrypt sendGridApiKey if it's being updated
    if (updates.sendGridApiKey) {
      updates.sendGridApiKey = encrypt(sanitize(updates.sendGridApiKey));
    }

    const tenant = await Tenant.findByIdAndUpdate(
      req.params.id,
      updates, // Apply all updates
      { new: true, runValidators: true }
    );

    if (!tenant) {
      logAction("Tenant Not Found", `Tenant ID: ${req.params.id}`);
      return res.status(404).json({ error: "Tenant not found" });
    }

    logAction("Tenant Updated", `Tenant ID: ${req.params.id}`);
    res.status(200).json(tenant);
  } catch (error) {
    logAction("Error Updating Tenant", error.message);
    res.status(500).json({ error: "Server error" });
  }
};

// Delete a tenant
exports.deleteTenant = async (req, res) => {
  try {
    logAction("Deleting Tenant", `Tenant ID: ${req.params.id}`);

    const tenant = await Tenant.findByIdAndDelete(req.params.id);

    if (!tenant) {
      logAction("Tenant Not Found", `Tenant ID: ${req.params.id}`);
      return res.status(404).json({ error: "Tenant not found" });
    }

    logAction("Tenant Deleted", `Tenant ID: ${req.params.id}`);
    res.status(200).json({ message: "Tenant deleted successfully" });
  } catch (error) {
    logAction("Error Deleting Tenant", error.message);
    res.status(500).json({ error: "Server error" });
  }
};
