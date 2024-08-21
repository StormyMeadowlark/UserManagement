const BlacklistedToken = require("../models/BlacklistedToken");

const blacklistToken = async (token, expiresIn) => {
  try {
    const expiryDate = new Date(Date.now() + expiresIn * 1000); // Convert seconds to milliseconds
    const blacklistedToken = new BlacklistedToken({
      token,
      expiresAt: expiryDate,
    });
    await blacklistedToken.save();
    console.log(
      `Token blacklisted: ${token}, expires at: ${expiryDate.toISOString()}`
    );
    return { success: true, message: "Token successfully blacklisted" };
  } catch (error) {
    console.error(`Error blacklisting token: ${token}`, error);
    return { success: false, message: "Failed to blacklist token", error };
  }
};

const isBlacklisted = async (token) => {
  try {
    const tokenDoc = await BlacklistedToken.findOne({ token });
    const isBlacklisted = !!tokenDoc;
    console.log(`Token check: ${token}, blacklisted: ${isBlacklisted}`);
    return isBlacklisted;
  } catch (error) {
    console.error(`Error checking if token is blacklisted: ${token}`, error);
    return false; // Assuming if there's an error, treat the token as not blacklisted to avoid unintended access blocks
  }
};

module.exports = {
  blacklistToken,
  isBlacklisted,
};
