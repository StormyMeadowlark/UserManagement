const nodemailer = require("nodemailer");
const { decrypt } = require("../config/config");

const sendEmail = async (to, subject, text, tenant) => {
  
  // Create a transporter using the tenant's SendGrid API key
  const sendGridApiKey = decrypt(tenant.sendGridApiKey);
  const transporter = nodemailer.createTransport({
    host: "smtp.sendgrid.net",
    port: 587,
    secure: false,
    auth: {
      user: "apikey", // This is the literal string 'apikey'
      pass: sendGridApiKey, // Tenant-specific SendGrid API key
    },
  });

  const mailOptions = {
    to,
    from: tenant.verifiedSenderEmail, // Tenant-specific sender email
    subject,
    text,
  };

  return transporter.sendMail(mailOptions);
};

module.exports = {
  sendEmail,
};
