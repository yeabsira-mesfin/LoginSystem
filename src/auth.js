const crypto = require("node:crypto");
const { verifyAccessToken } = require("./tokens");
const { usersByEmail } = require("./store");

function requireAuth(req, res, next) {
  const header = req.get("authorization") || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "authentication required" });
  }

  try {
    req.auth = verifyAccessToken(token);
    return next();
  } catch {
    return res.status(401).json({ error: "authentication required" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.auth || req.auth.role !== role) {
      return res.status(403).json({ error: "forbidden" });
    }
    return next();
  };
}

function getUserById(id) {
  for (const user of usersByEmail.values()) {
    if (user.id === id) return user;
  }
  return null;
}

function newUserId() {
  return crypto.randomUUID();
}

module.exports = { requireAuth, requireRole, getUserById, newUserId };
