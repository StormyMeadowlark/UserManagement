module.exports = (req, res, next) => {
  const tenantId = req.headers["x-tenant-id"];
  if (!tenantId) {
    return res.status(400).json({ message: "X-Tenant-Id header is required" });
  }
  req.tenantId = tenantId;
  next();
};
