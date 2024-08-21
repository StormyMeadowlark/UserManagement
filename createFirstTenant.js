const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Tenant = require("../client-endpoints/models/Tenant"); // Adjust path as needed
const User = require("./models/User"); // Adjust path as needed
const dotenv = require("dotenv");
const crypto = require("crypto");

dotenv.config();

async function createFirstTenantAndSuperAdmin() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log("Connected to MongoDB");

    // Create Tenant
    const tenantName = "FirstTenant";
    const tenantEmail = "stormymeadowlark@gmail.com";
    const apiKey = crypto.randomBytes(32).toString("hex");

    const tenant = new Tenant({
      name: tenantName,
      contactEmail: tenantEmail,
      services: [
        {
          serviceType: "UserManagement",
          apiKey,
        },
      ],
      subscriptionPlan: "Premium",
  
    });

    await tenant.save();

    console.log("Tenant created:", tenant);

    // Create SuperAdmin User
    const superAdminUsername = "superadmin";
    const superAdminEmail = "herken.ashlee@gmail.com";
    const superAdminPassword = "Password123";

    const hashedPassword = await bcrypt.hash(superAdminPassword, 10);

    const user = new User({
      username: superAdminUsername,
      email: superAdminEmail,
      password: hashedPassword,
      role: "SuperAdmin",
      tenant: tenant._id,
      emailVerified: true,
    });

    await user.save();

    console.log("SuperAdmin created:", user);

    // Generate JWT Token for SuperAdmin
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    console.log("JWT Token generated:", token);
    console.log("API Key for Tenant:", apiKey);

    // Close the database connection
    await mongoose.disconnect();
  } catch (error) {
    console.error("Error creating tenant and SuperAdmin:", error);
  }
}

createFirstTenantAndSuperAdmin();
