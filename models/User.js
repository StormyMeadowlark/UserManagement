const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const validator = require("validator");

const UserSchema = new mongoose.Schema(
  {
    // Basic User Information
    firstName: { type: String, trim: true },
    lastName: { type: String, trim: true },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
      validate: [validator.isEmail, "Invalid email address"],
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },

    // Contact Information
    phoneNumber: {
      type: String,
      validate: [validator.isMobilePhone, "Invalid phone number"],
    },
    address: {
      street: { type: String, trim: true },
      city: { type: String, trim: true },
      state: { type: String, trim: true },
      postalCode: { type: String, trim: true },
      country: { type: String, trim: true, default: "USA" },
    },
    profilePicture: { type: String, default: null },

    // Authentication & Security
    role: {
      type: String,
      enum: [
        "Admin",
        "Editor",
        "Viewer",
        "SuperAdmin",
        "Guest",
        "Tenant",
        "Mechanic",
        "User",
      ],
      default: "User",
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    emailVerified: { type: Boolean, default: false },
    verificationToken: String,
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorMethod: {
      type: String,
      enum: ["SMS", "Email", "AuthenticatorApp"],
    },

    // Preferences & Activity Tracking
    isSubscribedToNewsletter: { type: Boolean, default: false },
    preferredLanguage: { type: String, default: "en" },
    timezone: { type: String, default: "UTC" },
    lastLogin: { type: Date },
    lastPasswordChange: { type: Date },
    lastActivity: { type: Date },
    status: {
      type: String,
      enum: ["Active", "Suspended", "Deactivated"],
      default: "Active",
      index: true,
    },

    // Relationships & Associations
    tenant: { type: mongoose.Schema.Types.ObjectId, ref: "Tenant" },
    savedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post" }],
    socialAccounts: {
      googleId: String,
      facebookId: String,
      githubId: String,
    },

    // API & Security Keys
    apiKeys: [{ key: String, createdAt: { type: Date, default: Date.now } }],

    // Optional Extensibility
    meta: {
      managedVehicles: [
        { type: mongoose.Schema.Types.ObjectId, ref: "Vehicle" },
      ], // Vehicles the user manages (Admin/Mechanic)
      assignedRepairs: [
        { type: mongoose.Schema.Types.ObjectId, ref: "Service" },
      ], // Service tasks for mechanics
      customFields: mongoose.Schema.Types.Mixed, // Additional custom fields for extensibility
    },
  },
  { timestamps: true }
);

// Hash the password before saving
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare passwords
UserSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

UserSchema.index({ email: 1, username: 1, phoneNumber: 1, tenant: 1 }, { unique: true }});

const User = mongoose.model("User", UserSchema);

module.exports = User;
