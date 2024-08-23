const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");

const TenantSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    contactEmail: {
      type: String,
      required: true,
      validate: [validator.isEmail, "Invalid email address"],
      lowercase: true,
      trim: true,
      unique: true, // Ensure that each tenant has a unique contact email
    },
    domain: {
      type: String,
      required: true,
      unique: true,
      trim: true, // Ensure that each tenant has a unique domain
    },
    sendGridApiKey: {
      type: String,
      // Encrypt the key before storing
    },
    verifiedSenderEmail: { type: String },
    apiKey: {
      type: String,
      required: true,
      unique: true,
      select: false, // Prevent API key from being returned in queries by default
    },
    status: {
      type: String,
      enum: ["Active", "Inactive", "Pending"],
      default: "Active",
    },
  },
  { timestamps: true }
);

TenantSchema.pre("save", async function (next) {
  if (!this.isModified("apiKey")) return next();
  const salt = await bcrypt.genSalt(10);
  this.apiKey = await bcrypt.hash(this.apiKey, salt);
  next();
});
// Add an index to the `name` and `contactEmail` fields for quick lookup
TenantSchema.index({ name: 1, contactEmail: 1 });

// Ensure `apiKey` is always unique by creating an index on it
TenantSchema.index({ apiKey: 1 }, { unique: true });

const Tenant = mongoose.model("Tenant", TenantSchema);
module.exports = Tenant;
