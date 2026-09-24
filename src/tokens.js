const jwt = require("jsonwebtoken");
const { randomToken, hashToken } = require("./crypto");
const { sessionsByHash } = require("./store");

function secret() {
  const value = process.env.JWT_SECRET;
  if (!value || value.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters");
  }
  return value;
}

function issueAccessToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    secret(),
    { algorithm: "HS256", expiresIn: "15m", issuer: "secure-auth-service", audience: "secure-auth-api" }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, secret(), {
    algorithms: ["HS256"],
    issuer: "secure-auth-service",
    audience: "secure-auth-api"
  });
}

function createRefreshSession(userId) {
  const token = randomToken();
  const tokenHash = hashToken(token);
  sessionsByHash.set(tokenHash, {
    userId,
    revoked: false,
    createdAt: Date.now()
  });
  return token;
}

function rotateRefreshToken(oldToken) {
  const oldHash = hashToken(oldToken);
  const session = sessionsByHash.get(oldHash);

  if (!session || session.revoked) {
    return null;
  }

  session.revoked = true;
  const newToken = createRefreshSession(session.userId);
  return { userId: session.userId, token: newToken };
}

function revokeRefreshToken(token) {
  const tokenHash = hashToken(token);
  const session = sessionsByHash.get(tokenHash);
  if (!session) return false;
  session.revoked = true;
  return true;
}

module.exports = {
  issueAccessToken,
  verifyAccessToken,
  createRefreshSession,
  rotateRefreshToken,
  revokeRefreshToken
};
