const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const validator = require("validator");

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3, // Example validation for username
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      validate: [validator.isEmail, "Invalid email address"], // Email validation
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["Admin", "Editor", "Viewer", "SuperAdmin", "Guest", "Tenant"],
      default: "Viewer",
    },
    tenant: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Tenant",

    },
    status: {
      type: String,
      enum: ["Active", "Suspended", "Deactivated"],
      default: "Active",
      index: true, // Index for faster queries
    },
    lastLogin: {
      type: Date,
    },
    profilePicture: {
      type: String, // URL to the profile picture stored in cloud storage
    },
    savedPosts: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Post",
      },
    ],
    resetPasswordToken: String, // Token for password reset
    resetPasswordExpires: Date, // Expiration time for password reset token
    emailVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: String, // Token for email verification
    apiKey: {
      type: String,
      select: false, // Prevent API key from being returned in queries by default
    },
  },
  { timestamps: true }
);

// Pre-save hook to hash password before saving
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare password for login
UserSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Indexes
UserSchema.index({ email: 1, username: 1 }); // Unique index on email and username

const User = mongoose.model("User", UserSchema);
module.exports = User;
