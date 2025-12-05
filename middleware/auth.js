const User = require("../models/User");
const jwt = require("jsonwebtoken");

async function requireAuth(req, res, next) {
  try {
    const raw = req.get("Authorization") || "";
    const token = raw.startsWith("Bearer ") ? raw.slice(7) : null;

    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    let payload;

    try {
      // TRY verifying normally
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        // Allow expired tokens to be refreshed
        req.tokenExpired = true;
        payload = jwt.decode(token);
      } else {
        return res.status(401).json({ message: "Token invalid" });
      }
    }

    if (!payload?.sub) {
      return res.status(401).json({ message: "Token invalid" });
    }

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // Only check strict match when NOT expired
    if (!req.tokenExpired && user.accessToken !== token) {
      return res.status(401).json({ message: "Token invalid or expired" });
    }

    req.userId = user._id.toString();
    next();
  } catch (err) {
    console.error("requireAuth:", err);
    return res.status(401).json({ message: "Unauthorized" });
  }
}

module.exports = { requireAuth };
