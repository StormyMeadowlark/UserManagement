// models/BlacklistedToken.js

const mongoose = require("mongoose");

const BlacklistedTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});

BlacklistedTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const BlacklistedToken = mongoose.model(
  "BlacklistedToken",
  BlacklistedTokenSchema
);
module.exports = BlacklistedToken;
