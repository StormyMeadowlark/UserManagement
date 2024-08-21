const {
  S3Client,
  PutObjectCommand,
  DeleteObjectCommand,
} = require("@aws-sdk/client-s3");
const { v4: uuidv4 } = require("uuid");
const Media = require("../models/Media");
const { validationResult } = require("express-validator");
const { logAction } = require("../utils/logger"); // Assuming you have a logging utility
require("dotenv").config();

// Configure AWS SDK for DigitalOcean Spaces
const s3Client = new S3Client({
  endpoint: `https://${process.env.DO_SPACES_ENDPOINT}`, // Your Spaces endpoint, e.g., nyc3.digitaloceanspaces.com
  region: "us-east-1", // Required, but doesn't affect Spaces
  credentials: {
    accessKeyId: process.env.DO_SPACES_KEY,
    secretAccessKey: process.env.DO_SPACES_SECRET,
  },
  forcePathStyle: false, // Optional, can be true or false depending on your needs
});

// Upload a media file
exports.uploadMedia = async (req, res) => {
  // Validation check
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logAction("Validation Error", JSON.stringify(errors.array()));
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request
    const file = req.file;
    const filename = `${uuidv4()}.${file.originalname.split(".").pop()}`; // Use 'filename' instead of 'key'

    logAction(
      "Uploading Media",
      `Tenant ID: ${tenantId}, Filename: ${filename}`
    );

    const params = {
      Bucket: process.env.DO_SPACES_BUCKET,
      Key: filename,
      Body: file.buffer,
      ContentType: file.mimetype,
      ACL: "public-read",
    };

    const command = new PutObjectCommand(params);
    const data = await s3Client.send(command);

    const media = new Media({
      tenant: tenantId, // Associate the media with the tenant
      filename: filename, // Save as 'filename'
      url: `https://${params.Bucket}.${process.env.DO_SPACES_ENDPOINT}/${filename}`,
      type: file.mimetype,
      uploadDate: Date.now(),
    });

    await media.save();
    logAction(
      "Media Uploaded",
      `Tenant ID: ${tenantId}, Media ID: ${media._id}`
    );
    res.status(201).json(media);
  } catch (error) {
    logAction(
      "Error Uploading Media",
      `Tenant ID: ${req.tenant._id}, Error: ${error.message}`
    );
    res.status(500).json({ error: "Error uploading media" });
  }
};

// List all media files for the tenant
exports.getAllMedia = async (req, res) => {
  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request

    logAction("Fetching Media Files", `Tenant ID: ${tenantId}`);

    const mediaFiles = await Media.find({ tenant: tenantId }).sort({
      uploadDate: -1,
    });
    res.status(200).json(mediaFiles);
  } catch (error) {
    logAction(
      "Error Fetching Media Files",
      `Tenant ID: ${req.tenant._id}, Error: ${error.message}`
    );
    res.status(500).json({ error: "Error fetching media files" });
  }
};

// Get a specific media file by ID
exports.getMediaById = async (req, res) => {
  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request

    logAction(
      "Fetching Media File",
      `Tenant ID: ${tenantId}, Media ID: ${req.params.id}`
    );

    const media = await Media.findOne({ _id: req.params.id, tenant: tenantId }); // Ensure the media belongs to the tenant
    if (!media) {
      logAction(
        "Media File Not Found",
        `Tenant ID: ${tenantId}, Media ID: ${req.params.id}`
      );
      return res.status(404).json({ error: "Media file not found" });
    }
    res.status(200).json(media);
  } catch (error) {
    logAction(
      "Error Fetching Media File",
      `Tenant ID: ${req.tenant._id}, Media ID: ${req.params.id}, Error: ${error.message}`
    );
    res.status(500).json({ error: "Error fetching media file" });
  }
};

// Delete a media file
exports.deleteMedia = async (req, res) => {
  try {
    const tenantId = req.tenant._id; // Get the tenant ID from the request

    logAction(
      "Deleting Media File",
      `Tenant ID: ${tenantId}, Media ID: ${req.params.id}`
    );

    const media = await Media.findOne({ _id: req.params.id, tenant: tenantId }); // Ensure the media belongs to the tenant
    if (!media) {
      logAction(
        "Media File Not Found",
        `Tenant ID: ${tenantId}, Media ID: ${req.params.id}`
      );
      return res.status(404).json({ error: "Media file not found" });
    }

    // Delete from DigitalOcean Spaces
    const params = {
      Bucket: process.env.DO_SPACES_BUCKET,
      Key: media.filename,
    };
    const command = new DeleteObjectCommand(params);
    await s3Client.send(command);

    // Delete from database
    await media.deleteOne();
    logAction(
      "Media File Deleted",
      `Tenant ID: ${tenantId}, Media ID: ${req.params.id}`
    );
    res.status(200).json({ message: "Media file deleted successfully" });
  } catch (error) {
    logAction(
      "Error Deleting Media File",
      `Tenant ID: ${req.tenant._id}, Media ID: ${req.params.id}, Error: ${error.message}`
    );
    res.status(500).json({ error: "Error deleting media file" });
  }
};
