const nodemailer = require("nodemailer");

const sendEmail = async (to, subject, text, tenant) => {
  // Create a transporter using the tenant's SendGrid API key
  const transporter = nodemailer.createTransport({
    host: "smtp.sendgrid.net",
    port: 587,
    secure: false,
    auth: {
      user: "apikey", // This is the literal string 'apikey'
      pass: tenant.sendGridApiKey, // Tenant-specific SendGrid API key
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
