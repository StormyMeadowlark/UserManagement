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
      minlength: 3,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true, // Ensure unique email
      validate: [validator.isEmail, "Invalid email address"],
    },
    password: {
      type: String,
      required: true,
      minlength: 6, // Example minimum length
    },
    role: {
      type: String,
      enum: ["Admin", "Editor", "Viewer", "SuperAdmin", "Guest", "Tenant"],
    },
    tenant: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Tenant",
    },
    status: {
      type: String,
      enum: ["Active", "Suspended", "Deactivated"],
      default: "Active",
      index: true,
    },
    lastLogin: {
      type: Date,
    },
    profilePicture: {
      type: String,
    },
    savedPosts: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Post",
      },
    ],
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    emailVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: String,
  },
  { timestamps: true }
);

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

UserSchema.index({ email: 1, username: 1 });

const User = mongoose.model("User", UserSchema);
module.exports = User;
