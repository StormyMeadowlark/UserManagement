function sanitize(input) {
  if (!input || typeof input !== "object") return {};

  const sanitizedInput = {};

  for (const key in input) {
    if (typeof input[key] === "string") {
      sanitizedInput[key] = input[key].trim(); // Trim whitespace
    } else if (typeof input[key] === "object") {
      sanitizedInput[key] = sanitize(input[key]); // Recursively sanitize
    } else {
      sanitizedInput[key] = input[key]; // Copy non-string values as is
    }
  }

  return sanitizedInput;
}

module.exports = sanitize;
