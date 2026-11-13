import bcrypt from "bcryptjs";
import { UserRole, UserStatus } from "@prisma/client";
import { prisma } from "./prisma.js";
import { signAuthToken, verifyAuthToken, type AuthUser } from "./auth.js";

export type PostgresAuthRecord = {
  id: string;
  email: string;
  name: string;
  role: string;
  passwordHash: string;
  status: "PENDING" | "ACTIVE" | "DISABLED" | "LOCKED";
  authVersion: number;
};

export type PostgresAuthStore = {
  findByEmail(email: string): Promise<PostgresAuthRecord | null>;
  findById(id: string): Promise<PostgresAuthRecord | null>;
};

export type ValidatedPostgresUser = AuthUser & { status: UserStatus };

export const prismaAuthStore: PostgresAuthStore = {
  async findByEmail(email) {
    const user = await prisma.user.findUnique({ where: { email } });
    return user && {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      passwordHash: user.passwordHash,
      status: user.status,
      authVersion: user.authVersion,
    };
  },
  async findById(id) {
    const user = await prisma.user.findUnique({ where: { id } });
    return user && {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      passwordHash: user.passwordHash,
      status: user.status,
      authVersion: user.authVersion,
    };
  },
};

function toAuthUser(user: PostgresAuthRecord): AuthUser {
  return { id: user.id, email: user.email, name: user.name, role: user.role, authVersion: user.authVersion };
}

function isBcryptHash(value: string): boolean {
  return /^\$2[aby]\$\d{2}\$/.test(value);
}

export async function authenticatePostgresUser(
  store: PostgresAuthStore,
  email: string,
  password: string,
  secret: string,
): Promise<{ token: string; user: AuthUser } | null> {
  const user = await store.findByEmail(email);
  if (!user || user.status !== "ACTIVE" || !isBcryptHash(user.passwordHash)) return null;
  if (!bcrypt.compareSync(password, user.passwordHash)) return null;
  const safeUser = toAuthUser(user);
  return { token: signAuthToken(safeUser, secret), user: safeUser };
}

export async function validatePostgresToken(
  store: PostgresAuthStore,
  token: string,
  secret: string,
): Promise<ValidatedPostgresUser> {
  const tokenUser = verifyAuthToken(token, secret);
  const currentUser = await store.findById(tokenUser.id);
  if (
    !currentUser
    || currentUser.status !== "ACTIVE"
    || currentUser.role !== tokenUser.role
    || currentUser.authVersion !== tokenUser.authVersion
  ) {
    throw new Error("Invalid or expired token");
  }
  return {
    id: currentUser.id,
    email: currentUser.email,
    name: currentUser.name,
    role: currentUser.role,
    authVersion: currentUser.authVersion,
    status: currentUser.status,
  };
}

export async function updatePostgresUserStatus(id: string, status: UserStatus): Promise<void> {
  await prisma.user.update({
    where: { id },
    data: { status, authVersion: { increment: 1 } },
  });
}

export async function updatePostgresUserRole(id: string, role: UserRole): Promise<void> {
  await prisma.user.update({
    where: { id },
    data: { role, authVersion: { increment: 1 } },
  });
}

export async function updatePostgresUserPassword(id: string, password: string): Promise<void> {
  if (Buffer.byteLength(password, "utf8") > 72) {
    throw new RangeError("Password must be 72 UTF-8 bytes or fewer");
  }
  await prisma.user.update({
    where: { id },
    data: { passwordHash: bcrypt.hashSync(password, 12), authVersion: { increment: 1 } },
  });
}
