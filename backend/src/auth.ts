import jwt from "jsonwebtoken";

export type AuthUser = {
  id: string;
  email: string;
  name: string;
  role: string;
  authVersion: number;
};

export function getJwtSecret(nodeEnv = process.env.NODE_ENV, configuredSecret = process.env.JWT_SECRET): string {
  if (nodeEnv === "production" && (!configuredSecret || configuredSecret.length < 32)) {
    throw new Error("JWT_SECRET must be configured with at least 32 characters in production");
  }
  return configuredSecret ?? "development-only-change-me";
}

export function signAuthToken(user: AuthUser, secret: string): string {
  return jwt.sign(
    { sub: user.id, email: user.email, name: user.name, role: user.role, authVersion: user.authVersion },
    secret,
    { expiresIn: "15m" },
  );
}

export function verifyAuthToken(token: string, secret: string): AuthUser {
  const payload = jwt.verify(token, secret);
  if (typeof payload !== "object" || payload === null) {
    throw new Error("Invalid token payload");
  }
  if (
    typeof payload.sub !== "string"
    || typeof payload.email !== "string"
    || typeof payload.name !== "string"
    || typeof payload.role !== "string"
    || typeof payload.authVersion !== "number"
    || !Number.isInteger(payload.authVersion)
    || payload.authVersion < 0
  ) {
    throw new Error("Invalid token claims");
  }
  return {
    id: payload.sub,
    email: payload.email,
    name: payload.name,
    role: payload.role,
    authVersion: payload.authVersion,
  };
}
