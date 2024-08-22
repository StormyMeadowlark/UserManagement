const nodemailer = require("nodemailer");
const { decrypt } = require("../config/config");

const sendEmail = async (to, from, subject, text, apikey) => {
  try {
    // Log the encrypted API key for debugging
    console.log("Encrypted API Key:", apikey);

    // Decrypt the tenant's SendGrid API key
    const decryptedApiKey = decrypt(apikey);

    // Log the decrypted API key for debugging
    console.log("Decrypted API Key:", decryptedApiKey);

    // Validate the decrypted API key
    if (!decryptedApiKey) {
      throw new Error("Decryption failed, API key is undefined or invalid.");
    }

    // Create a transporter using the tenant's decrypted SendGrid API key
    const transporter = nodemailer.createTransport({
      host: "smtp.sendgrid.net",
      port: 587,
      secure: false,
      auth: {
        user: "apikey", // This is the literal string 'apikey'
        pass: decryptedApiKey, // Tenant-specific decrypted SendGrid API key
      },
    });

    const mailOptions = {
      to,
      from, // Tenant-specific sender email
      subject,
      text,
    };

    // Send the email and log the success
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent successfully:", info.messageId);
  } catch (error) {
    console.error("Error sending email:", error.message);
    throw new Error("Email could not be sent");
  }
};

module.exports = {
  sendEmail,
};
