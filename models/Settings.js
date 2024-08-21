const mongoose = require("mongoose");
const validator = require("validator");

const SettingsSchema = new mongoose.Schema(
  {
    tenant: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Tenant",
      required: true,
      unique: true, // Each tenant has one settings document
    },
    siteName: { type: String, required: true }, // Consider making this required
    siteUrl: {
      type: String,
      default: "http://localhost",
      validate: [validator.isURL, "Invalid URL"], // URL validation
    },
    timezone: { type: String, default: "UTC" },
    language: { type: String, default: "en" },
    maintenanceMode: { type: Boolean, default: false },
    theme: { type: String, enum: ["light", "dark"], default: "light" },
    logo: {
      type: String,
      validate: [validator.isURL, "Invalid URL"], // URL validation
    },
    favicon: {
      type: String,
      validate: [validator.isURL, "Invalid URL"], // URL validation
    },
    registrationEnabled: { type: Boolean, default: true },
    passwordStrength: { type: String, default: "medium" },
    emailVerification: { type: Boolean, default: false },
    seoDefaults: {
      metaTitle: { type: String },
      metaDescription: { type: String, default: "Default description" },
      metaKeywords: [String],
    },
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: false },
    },
    security: {
      ipWhitelist: [String],
      loginAttemptsLimit: { type: Number, default: 5 },
    },
    integrations: {
      googleAnalytics: { type: String }, // Google Analytics tracking ID
      socialMedia: {
        facebook: { type: String },
        twitter: { type: String },
      },
    },
    backups: {
      autoBackupEnabled: { type: Boolean, default: true },
      backupFrequency: { type: String, default: "daily" },
    },
  },
  { timestamps: true }
);

// Adding index to the tenant field
SettingsSchema.index({ tenant: 1 });

const Settings = mongoose.model("Settings", SettingsSchema);
module.exports = Settings;
