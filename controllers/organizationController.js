const Organization = require("../models/Organization");
const sanitize  = require("../utils/sanitizer"); // Assuming you have a sanitizer utility
const logAction = require("../utils/logger"); // Assuming you have a logging utility

// Create a new organization
exports.createOrganization = async (req, res) => {
  try {
    console.log("Incoming request body:", req.body); // Log incoming request body

    const { tenantId } = req.params; // Extract tenantId from request params
    const organizationData = sanitize(req.body); // Sanitize input data
    console.log("Sanitized organization data:", organizationData); // Log sanitized data

    // Validate that required fields are present
    if (!organizationData.name || !organizationData.type) {
      console.error(
        "Sanitized data is missing required fields:",
        organizationData
      );
      return res.status(400).json({ error: "Name and type are required." });
    }

    const newOrganization = new Organization({
      ...organizationData,
      tenantId: tenantId, // Add tenantId if needed
    });

    // Save the new organization
    const savedOrganization = await newOrganization.save();
    res.status(201).json(savedOrganization);
  } catch (error) {
    console.error("Error creating organization:", error.message);
    res.status(500).json({ error: "Error creating organization" });
  }
};
// Get all organizations for a tenant
exports.getOrganizations = async (req, res) => {
  try {
    const { tenantId } = req.params;
    const organizations = await Organization.find({ tenantId });
    res.status(200).json(organizations);
  } catch (error) {
    logAction("Error fetching organizations", error.message);
    res.status(500).json({ error: "Error fetching organizations" });
  }
};

// Get an organization by ID
exports.getOrganizationById = async (req, res) => {
  try {
    const { tenantId, id } = req.params;
    const organization = await Organization.findOne({ _id: id, tenantId });

    if (!organization) {
      return res.status(404).json({ error: "Organization not found" });
    }

    res.status(200).json(organization);
  } catch (error) {
    logAction("Error fetching organization", error.message);
    res.status(500).json({ error: "Error fetching organization" });
  }
};

// Update an organization
exports.updateOrganization = async (req, res) => {
  try {
    const { tenantId, id } = req.params;
    const organizationData = sanitize(req.body); // Sanitize input data

    const updatedOrganization = await Organization.findOneAndUpdate(
      { _id: id, tenantId },
      organizationData,
      { new: true } // Return the updated document
    );

    if (!updatedOrganization) {
      return res.status(404).json({ error: "Organization not found" });
    }

    res.status(200).json(updatedOrganization);
  } catch (error) {
    logAction("Error updating organization", error.message);
    res.status(500).json({ error: "Error updating organization" });
  }
};

// Delete an organization
exports.deleteOrganization = async (req, res) => {
  try {
    const { tenantId, id } = req.params;
    const deletedOrganization = await Organization.findOneAndDelete({
      _id: id,
      tenantId,
    });

    if (!deletedOrganization) {
      return res.status(404).json({ error: "Organization not found" });
    }

    res.status(204).json({ message: "Organization deleted successfully" });
  } catch (error) {
    logAction("Error deleting organization", error.message);
    res.status(500).json({ error: "Error deleting organization" });
  }
};
