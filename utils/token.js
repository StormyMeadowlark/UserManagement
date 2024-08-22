const jwt = require("jsonwebtoken");

const generateToken = (user) => {
  const payload = {
    _id: user._id,
    tenant: user.tenant._id,
    role: user.role,
  };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "30d" });
};

module.exports = { generateToken };
