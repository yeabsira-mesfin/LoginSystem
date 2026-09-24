const express = require("express");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

const { hashPassword, verifyPassword } = require("./crypto");
const { usersByEmail } = require("./store");
const {
  issueAccessToken,
  createRefreshSession,
  rotateRefreshToken,
  revokeRefreshToken
} = require("./tokens");
const { requireAuth, requireRole, getUserById, newUserId } = require("./auth");

function validEmail(value) {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

function validPassword(value) {
  return typeof value === "string" && value.length >= 12 && value.length <= 128;
}

function createApp() {
  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(helmet());
  app.use(express.json({ limit: "16kb", strict: true }));

  const loginLimiter = rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "too many authentication attempts" }
  });

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.post("/auth/register", async (req, res) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = req.body?.password;

    if (!validEmail(email) || !validPassword(password)) {
      return res.status(400).json({ error: "invalid registration data" });
    }

    if (usersByEmail.has(email)) {
      return res.status(409).json({ error: "account already exists" });
    }

    const user = {
      id: newUserId(),
      email,
      passwordHash: await hashPassword(password),
      role: "user"
    };

    usersByEmail.set(email, user);
    return res.status(201).json({ id: user.id, email: user.email, role: user.role });
  });

  app.post("/auth/login", loginLimiter, async (req, res) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = req.body?.password;
    const user = usersByEmail.get(email);

    const valid = Boolean(user) && await verifyPassword(password || "", user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: "invalid credentials" });
    }

    return res.json({
      accessToken: issueAccessToken(user),
      refreshToken: createRefreshSession(user.id),
      tokenType: "Bearer",
      expiresIn: 900
    });
  });

  app.post("/auth/refresh", (req, res) => {
    const refreshToken = req.body?.refreshToken;
    if (typeof refreshToken !== "string") {
      return res.status(400).json({ error: "refresh token required" });
    }

    const rotated = rotateRefreshToken(refreshToken);
    if (!rotated) {
      return res.status(401).json({ error: "invalid refresh token" });
    }

    const user = getUserById(rotated.userId);
    if (!user) {
      return res.status(401).json({ error: "invalid refresh token" });
    }

    return res.json({
      accessToken: issueAccessToken(user),
      refreshToken: rotated.token,
      tokenType: "Bearer",
      expiresIn: 900
    });
  });

  app.post("/auth/logout", (req, res) => {
    const refreshToken = req.body?.refreshToken;
    if (typeof refreshToken !== "string") {
      return res.status(400).json({ error: "refresh token required" });
    }

    revokeRefreshToken(refreshToken);
    return res.status(204).send();
  });

  app.get("/me", requireAuth, (req, res) => {
    const user = getUserById(req.auth.sub);
    if (!user) return res.status(404).json({ error: "user not found" });

    return res.json({ id: user.id, email: user.email, role: user.role });
  });

  app.get("/admin/metrics", requireAuth, requireRole("admin"), (_req, res) => {
    return res.json({
      users: usersByEmail.size,
      message: "RBAC-protected administrative endpoint"
    });
  });

  app.use((_req, res) => res.status(404).json({ error: "not found" }));

  return app;
}

module.exports = { createApp };
