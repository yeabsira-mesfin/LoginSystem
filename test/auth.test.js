const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");

process.env.JWT_SECRET = "x".repeat(48);

const { createApp } = require("../src/app");
const { clearStores, usersByEmail } = require("../src/store");

test.beforeEach(() => clearStores());

async function registerAndLogin(app, role = "user", email = "user@example.com") {
  await request(app)
    .post("/auth/register")
    .send({ email, password: "Correct-Horse-42!" });

  if (role === "admin") {
    const user = usersByEmail.get(email);
    user.role = "admin";
  }

  const login = await request(app)
    .post("/auth/login")
    .send({ email, password: "Correct-Horse-42!" });

  return login.body;
}

test("password policy rejects short passwords", async () => {
  const response = await request(createApp())
    .post("/auth/register")
    .send({ email: "user@example.com", password: "short" });

  assert.equal(response.status, 400);
});

test("login returns access and refresh tokens", async () => {
  const tokens = await registerAndLogin(createApp());
  assert.ok(tokens.accessToken);
  assert.ok(tokens.refreshToken);
  assert.equal(tokens.expiresIn, 900);
});

test("refresh token is rotated and old token cannot be reused", async () => {
  const app = createApp();
  const initial = await registerAndLogin(app);

  const firstRefresh = await request(app)
    .post("/auth/refresh")
    .send({ refreshToken: initial.refreshToken });

  assert.equal(firstRefresh.status, 200);
  assert.notEqual(firstRefresh.body.refreshToken, initial.refreshToken);

  const replay = await request(app)
    .post("/auth/refresh")
    .send({ refreshToken: initial.refreshToken });

  assert.equal(replay.status, 401);
});

test("logout revokes refresh token", async () => {
  const app = createApp();
  const tokens = await registerAndLogin(app);

  const logout = await request(app)
    .post("/auth/logout")
    .send({ refreshToken: tokens.refreshToken });

  assert.equal(logout.status, 204);

  const refresh = await request(app)
    .post("/auth/refresh")
    .send({ refreshToken: tokens.refreshToken });

  assert.equal(refresh.status, 401);
});

test("normal user is denied admin route", async () => {
  const app = createApp();
  const tokens = await registerAndLogin(app);

  const response = await request(app)
    .get("/admin/metrics")
    .set("authorization", `Bearer ${tokens.accessToken}`);

  assert.equal(response.status, 403);
});

test("admin role can access admin route", async () => {
  const app = createApp();
  const tokens = await registerAndLogin(app, "admin", "admin@example.com");

  const response = await request(app)
    .get("/admin/metrics")
    .set("authorization", `Bearer ${tokens.accessToken}`);

  assert.equal(response.status, 200);
});
