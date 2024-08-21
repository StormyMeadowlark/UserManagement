const mongoose = require("mongoose");
const validator = require("validator");

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
    },
    contactPhone: {
      type: String,
      validate: {
        validator: function (v) {
          return /\d{10}/.test(v); // Simple validation for a 10-digit number
        },
        message: (props) => `${props.value} is not a valid phone number!`,
      },
    },
    verifiedSenderEmail: { type: String },
    sendGridApiKey: { type: String },
    users: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    apiKey: {
      type: String,
      required: true,
      unique: true,
      select: false, // Prevent API key from being returned in queries by default
    },
    services: [
      {
        type: String,
        enum: ["CMS", "UserManagement"],
        required: true,
      },
    ],
    subscriptionPlan: {
      type: String,
      enum: ["Basic", "Standard", "Premium"],
      default: "Basic",
    },
    subscriptionStatus: {
      type: String,
      enum: ["Active", "Suspended", "Cancelled"],
      default: "Active",
      index: true, // Index for faster queries
    },
    settings: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Settings", // Reference the Settings model
    },
    apiUsage: {
      requests: { type: Number, default: 0 },
      dataStorage: { type: Number, default: 0 }, // in MB/GB
    },
    lastActive: {
      type: Date,
      default: Date.now,
    },
    status: {
      type: String,
      enum: ["Active", "Inactive", "Pending"],
      default: "Active",
      index: true, // Index for faster queries
    },
    isVerified: {
      type: Boolean,
      default: false,
      index: true, // Index for faster queries
    },
  },
  { timestamps: true }
);

// Add an index to the `name` and `contactEmail` fields
TenantSchema.index({ name: 1, contactEmail: 1 });

TenantSchema.pre("save", function (next) {
  if (this.isModified("sendGridApiKey")) {
    this.sendGridApiKey = encrypt(this.sendGridApiKey);
  }
  next();
});

const Tenant = mongoose.model("Tenant", TenantSchema);
module.exports = Tenant;
