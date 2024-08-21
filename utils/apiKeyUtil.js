const crypto = require("crypto");
const bcrypt = require("bcrypt");
const User = require("../models/User");

exports.generateApiKey = async (userId) => {
  try {
    // Fetch the user
    const user = await User.findById(userId);
    if (!user) {
      throw new Error("User not found");
    }

    // Generate a random API key
    const apiKey = crypto.randomBytes(32).toString("hex");

    // Hash the API key
    const salt = await bcrypt.genSalt(10);
    const hashedApiKey = await bcrypt.hash(apiKey, salt);

    // Store the hashed API key in the user's document
    user.apiKey = hashedApiKey;
    await user.save();

    // Return the plain API key (not hashed) to the caller
    return apiKey;
  } catch (error) {
    throw new Error(`Error generating API key: ${error.message}`);
  }
};
