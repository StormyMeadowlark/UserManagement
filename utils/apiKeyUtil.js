const crypto = require("crypto");
const bcrypt = require("bcrypt");
const User = require("../models/User");

exports.generateApiKey = async (tenantId) => {
  try {
    const tenant = await Tenant.findById(tenantId);
    if (!tenant) {
      throw new Error("Tenant not found");
    }

    const apiKey = crypto.randomBytes(32).toString("hex");
    const salt = await bcrypt.genSalt(10);
    const hashedApiKey = await bcrypt.hash(apiKey, salt);

    tenant.apiKey = hashedApiKey;
    await tenant.save();

    return apiKey;
  } catch (error) {
    throw new Error(`Error generating API key: ${error.message}`);
  }
};
