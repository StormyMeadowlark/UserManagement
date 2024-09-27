const mongoose = require("mongoose");

const organizationSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  type: {
    type: String,
    enum: ["auto repair", "dealership", "marketing agency", "SaaS", "other"],
    required: true,
  },
  tenantId: {
    // Include this field in your schema
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  address: {
    street: { type: String, trim: true },
    city: { type: String, trim: true },
    state: { type: String, trim: true },
    postalCode: { type: String, trim: true },
    country: { type: String, trim: true, default: "USA" },
  },
  contactDetails: {
    phone: { type: String, trim: true },
    email: { type: String, trim: true },
    website: { type: String, trim: true },
  },
  industrySpecificId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "IndustrySpecific",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Organization = mongoose.model("Organization", organizationSchema);

module.exports = Organization;
