const bcrypt = require("bcrypt");
const crypto = require("crypto");
const Tenant = require("../models/Tenant");
const { logAction } = require("../utils/logger");
const { encrypt } = require("../config/config");

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

    // Hash the API key before storing
    const salt = await bcrypt.genSalt(10);
    const hashedApiKey = await bcrypt.hash(apiKey, salt);

    // Encrypt the SendGrid API key before storing
    const encryptedSendGridApiKey = encrypt(sendGridApiKey);

    // Create and save the new tenant
    const tenant = new Tenant({
      name,
      contactEmail,
      sendGridApiKey: encryptedSendGridApiKey,
      verifiedSenderEmail,
      apiKey: hashedApiKey, // Store the hashed API key in the Tenant model
    });

    await tenant.save();

    logAction("Tenant Created", `Tenant ID: ${tenant._id}`);
    res.status(201).json({ tenant, apiKey }); // Return the plain API key to the client
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
exports.regenerateApiKey = async (req, res) => {
  try {
    const { tenantId } = req.params;

    // Find the tenant by ID
    const tenant = await Tenant.findById(tenantId);
    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    // Generate a new API key
    const newApiKey = crypto.randomBytes(32).toString("hex");

    // Hash the new API key
    const salt = await bcrypt.genSalt(10);
    const hashedApiKey = await bcrypt.hash(newApiKey, salt);

    // Update the tenant with the new API key
    tenant.apiKey = hashedApiKey;
    await tenant.save();

    logAction(
      "API Key Regenerated",
      `New API key generated for tenant ${tenant.name}`
    );

    // Send the new API key to the client
    res
      .status(200)
      .json({ message: "API key regenerated successfully", apiKey: newApiKey });
  } catch (error) {
    logAction("Error Regenerating API Key", error.message);
    res.status(500).json({ error: "Server error", details: error.message });
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
