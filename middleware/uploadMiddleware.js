const multer = require("multer");
const path = require("path");
const { logAction } = require("../utils/logger");

// Set up memory storage
const storage = multer.memoryStorage();

// Configure multer upload middleware
const upload = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // Limit file size to 2MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(
        new Error(
          "Invalid file type. Only JPEG, PNG, and GIF files are allowed."
        )
      );
    }
  },
}).any("file");

// Middleware for handling file uploads
const uploadProfilePictureMiddleware = (req, res, next) => {
  upload(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      logAction("Multer Error", err.message);
      return res.status(400).json({ error: err.message });
    } else if (err) {
      logAction("File Upload Error", err.message);
      return res.status(400).json({ error: err.message });
    }

    // If no errors, proceed to the next middleware/handler
    next();
  });
};

module.exports = uploadProfilePictureMiddleware;
