// middleware/attachTenant.js
module.exports = (req, res, next) => {
  const tenantId =
    req.params.tenantId || req.body.tenantId || req.query.tenantId;
  if (!tenantId) {
    return res.status(400).json({ message: "Tenant ID is required" });
  }
  req.tenantId = tenantId;
  next();
};
