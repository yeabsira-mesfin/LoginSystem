# Security Design

## Password storage

Passwords are never stored directly. The service uses Node.js scrypt with a unique random salt per account. Verification uses a timing-safe comparison.

## Access tokens

Access tokens are intentionally short lived. JWT verification pins the algorithm, issuer, and audience rather than accepting token metadata without constraints.

## Refresh tokens

Refresh tokens are random opaque values. Only a SHA-256 hash is stored server side. Every successful refresh revokes the previous token and issues a new one, reducing the usefulness of a replayed token.

## Revocation

Logout marks the presented refresh-token session as revoked. Access tokens remain short lived and expire naturally.

## Authorization

Authentication and authorization are separate controls. Protected routes first require a valid identity. Administrative routes then apply an explicit role check.

## Abuse resistance

The login endpoint has a dedicated rate limiter. Authentication failures use the same generic response whether the account is missing or the password is incorrect.

## Production extensions

- persistent database with unique constraints
- distributed session and rate-limit storage
- HTTPS and secure cookies where browser sessions are used
- MFA or WebAuthn for appropriate applications
- asymmetric signing keys or managed identity provider
- key rotation
- compromised-password screening
- account lockout and recovery policy
- structured security audit events
- device/session inventory
