const Tenant = require("../models/Tenant");
const { generateApiKey } = require("../utils/apiKeyUtil");


exports.generateApiKey = async (req, res) => {
  try {
    const apiKey = await generateApiKey(req.tenant._id);
    res.status(201).json({ message: "API key generated successfully", apiKey });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
};

exports.revokeApiKey = async (req, res) => {
  try {
    const tenantId = req.tenant._id;
    const tenant = await Tenant.findByIdAndUpdate(
      tenantId,
      { apiKey: null },
      { new: true }
    );

    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    res.status(200).json({ message: "API key revoked successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Internal Server Error", details: error.message });
  }
};
