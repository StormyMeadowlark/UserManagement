const fs = require("fs");
const path = require("path");
const { EventEmitter } = require("events");

const logFilePath = path.join(__dirname, "app.log");
const logEmitter = new EventEmitter();

// Function to append log messages asynchronously
const appendLog = (logMessage) => {
  fs.appendFile(logFilePath, logMessage, (err) => {
    if (err) {
      console.error("Error writing to log file", err);
    }
  });
};

// Listener that handles the log event
logEmitter.on("log", (logMessage) => {
  appendLog(logMessage);
});

const logAction = (action, message) => {
  const timestamp = new Date().toISOString();
  const logMessage = `${timestamp} - ${action}: ${message}\n`;

  // Emit the log message asynchronously
  logEmitter.emit("log", logMessage);
};

module.exports = {
  logAction,
};
