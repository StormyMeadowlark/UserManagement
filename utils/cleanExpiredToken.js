const BlacklistedToken = require("../models/BlacklistedToken");

const cleanExpiredTokens = async () => {
  try {
    const now = new Date();
    const result = await BlacklistedToken.deleteMany({
      expiresAt: { $lt: now },
    });
    console.log(
      `${
        result.deletedCount
      } expired tokens removed at ${new Date().toISOString()}`
    );
  } catch (error) {
    console.error(
      `Error cleaning expired tokens at ${new Date().toISOString()}:`,
      error
    );
  } finally {
    // Schedule the next cleanup
    setTimeout(cleanExpiredTokens, 24 * 60 * 60 * 1000); // Run every 24 hours
  }
};

// Start the initial cleanup
cleanExpiredTokens();
