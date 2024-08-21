const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const apiKeySchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  expiresAt: {
    type: Date,
    default: () => Date.now() + 30 * 24 * 60 * 60 * 1000, // Default to 30 days from creation
  },
  status: {
    type: String,
    enum: ["Active", "Revoked", "Expired"],
    default: "Active",
  },
});

// Pre-save hook to hash the API key before saving
apiKeySchema.pre("save", async function (next) {
  if (!this.isModified("key")) return next();
  const salt = await bcrypt.genSalt(10);
  this.key = await bcrypt.hash(this.key, salt);
  next();
});

// Method to verify the API key
apiKeySchema.methods.verifyKey = async function (inputKey) {
  return bcrypt.compare(inputKey, this.key);
};

const ApiKey = mongoose.model("ApiKey", apiKeySchema);

module.exports = ApiKey;
