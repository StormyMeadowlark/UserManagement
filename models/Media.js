const mongoose = require("mongoose");

const MediaSchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Tenant",
      required: true, // If media is always associated with a tenant
    },
    filename: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      enum: ["Image", "Video", "Document", "Other"], // Consistent descriptive labels
      required: true,
    },
    uploadDate: {
      type: Date,
      default: Date.now,
      index: true, // Index for faster queries on uploadDate
    },
    fileSize: {
      type: Number, // Store size in bytes
    },
  },
  { timestamps: true }
);

// Indexing filename for quicker searches if needed
MediaSchema.index({ filename: 1 });

const Media = mongoose.model("Media", MediaSchema);
module.exports = Media;
