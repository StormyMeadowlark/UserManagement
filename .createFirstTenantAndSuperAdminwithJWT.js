const mongoose = require("mongoose");
const Tenant = require("./models/Tenant");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
require("dotenv").config();

async function createFirstTenantAndSuperAdmin() {
  try {
    // Connect to the MongoDB database
    await mongoose.connect(process.env.MONGO_URI);

    // Ensure there is no existing tenant with the same contact email or name

    // Create the first tenant
    const apiKey = crypto.randomBytes(32).toString("hex");

    const tenant = new Tenant({
      name: "HEM Automotive",
      contactEmail: "hemauto.marketing@gmail.com",
      contactPhone: "7857302900",
      apiKey: apiKey,
      sendGridApiKey: "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",
      subscriptionPlan: "Premium",
      subscriptionStatus: "Active",
      status: "Active",
      isVerified: true,
      verifiedSenderEmail: "ashlee@stormymeadowlark.com",
    });

    await tenant.save();
    console.log("First tenant created:", tenant);

    // Hash the superAdmin password
    const superAdminPassword = "AriahJean2015!"; // Replace with your desired password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(superAdminPassword, salt);

    // Create the superAdmin user
    const superAdmin = new User({
      username: "Ashlee",
      email: "ashlee.herken@gmail.com",
      password: hashedPassword,
      role: "SuperAdmin",
      tenant: tenant._id, // Associate the superAdmin with the first tenant
      status: "Active",
      emailVerified: true,
    });

    await superAdmin.save();
    console.log("SuperAdmin user created:", superAdmin);

    // Generate JWT token for the superAdmin
    const token = jwt.sign(
      {
        _id: superAdmin._id,
        role: superAdmin.role,
        tenant: {
          id: tenant._id,
          name: tenant.name,
        },
      },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    console.log("JWT token generated for SuperAdmin:", token);

    // Disconnect from the database
    await mongoose.disconnect();
    console.log("Script completed successfully.");
    console.log("API Key:", apiKey);
    console.log("JWT Token:", token);
  } catch (error) {
    console.error("Error creating tenant and SuperAdmin:", error);
    await mongoose.disconnect();
  }
}

createFirstTenantAndSuperAdmin();
