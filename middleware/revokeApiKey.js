const revokeApiKey = async (req, res) => {
  try {
    const tenantId = req.tenant._id;
    const tenant = await Tenant.findById(tenantId);

    if (!tenant) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    tenant.apiKey = null;
    await tenant.save();

    res.status(200).json({ message: "API key revoked successfully" });
  } catch (error) {
    console.error("Error revoking API key:", error);
    res.status(500).json({ error: "Server error", details: error.message });
  }
};

module.exports = { revokeApiKey };
