const crypto = require("crypto");
const { validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Tenant = require("../models/Tenant");
const User = require("../models/User");

exports.createTenant = async (req, res) => {
  try {
    const { name, contactEmail, domain, sendGridApiKey, verifiedSenderEmail } =
      req.body;

    // Create a new tenant
    const newTenant = new Tenant({
      name,
      contactEmail,
      domain,
      sendGridApiKey,
      verifiedSenderEmail,
      apiKey: generateApiKey(), // Generate API key securely
    });

    await newTenant.save();

    // Generate a random password
    const randomPassword = crypto.randomBytes(8).toString("hex"); // 8 bytes = 16 characters

    // Automatically create a SuperAdmin user for this tenant
    const superAdminUser = new User({
      username: `${contactEmail.split("@")[0]}`, // Use the email prefix as username
      email: contactEmail,
      password,
      role: "SuperAdmin", // Assign the SuperAdmin role
      tenant: newTenant._id, // Correctly associate the ObjectId of the tenant
    });

    await superAdminUser.save();

    // Generate JWT token for SuperAdmin
    const token = jwt.sign(
      {
        userId: superAdminUser._id,
        tenantId: newTenant._id,
        role: "SuperAdmin",
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Return the token, tenant, user, and plain-text password in the response
    res.status(201).json({
      token,
      tenant: newTenant,
      user: superAdminUser,
      password: randomPassword, // Include the plain-text password in the response
    });
  } catch (error) {
    console.error("Error during tenant creation:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Function to generate a unique API key (example)
function generateApiKey() {
  return crypto.randomBytes(32).toString("hex");
}

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
