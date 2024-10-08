const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(express.json()); // Parse JSON request bodies

// Corrected CORS configuration
app.use(
  cors({
    origin: [
      "https://hemautomotive.com",
      "http://localhost:3000",
      "https://stormymeadowlark.com",
      "http://127.0.0.1:5173",
      "https://skynetrix.tech",
      "http://localhost:4000",
    ], // Correctly list allowed origins without wildcards
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "x-tenant-id", "Authorization"], // Include necessary headers
    credentials: true, // Optional: Enable this if you need to send credentials
  })
);

// MongoDB connection
console.log("Attempting to connect to MongoDB...");
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Import routes
const tenantRoutes = require("./routes/tenantRoutes");
const userRoutes = require("./routes/userRoutes");
const apiKeyRoutes = require("./routes/apiKeyRoutes");
const adminRoutes = require("./routes/adminRoutes");
const mediaRoutes = require("./routes/mediaRoutes");
const organizationRoutes = require("./routes/organizationRoutes")

// Routes
app.use("/api/tenants", tenantRoutes);
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/keys", apiKeyRoutes);
app.use("/api/media", mediaRoutes);
app.use("/api/organization", organizationRoutes)
// Basic route
app.get("/", (req, res) => {
  res.send("User Management API is running");
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
