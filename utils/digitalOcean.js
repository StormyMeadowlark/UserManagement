// utils/digitalOcean.js

const { S3Client, Endpoint } = require("@aws-sdk/client-s3");
require("dotenv").config();

// Log the DigitalOcean Spaces endpoint for debugging purposes
console.log("DO_SPACES_ENDPOINT:", process.env.DO_SPACES_ENDPOINT);

// Create an S3 client instance with the necessary configurations
const s3Client = new S3Client({
  endpoint: process.env.DO_SPACES_ENDPOINT,
  region: "us-east-1", // DigitalOcean Spaces is not region-specific, but you must provide a region
  credentials: {
    accessKeyId: process.env.DO_SPACES_KEY,
    secretAccessKey: process.env.DO_SPACES_SECRET,
  },
});

module.exports = s3Client;