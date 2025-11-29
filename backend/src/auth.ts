import { Request, Response, NextFunction } from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";

// Configuration
const SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
const SESSION_COOKIE_NAME = "excalidash_session";
const BCRYPT_ROUNDS = 12;

// Login rate limiting
const LOGIN_RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const LOGIN_MAX_ATTEMPTS = 5;
const loginAttempts = new Map<string, { count: number; resetTime: number }>();

// Session store
interface Session {
  id: string;
  createdAt: number;
  expiresAt: number;
}

const sessions = new Map<string, Session>();

// Cleanup expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(id);
    }
  }
}, 5 * 60 * 1000);

// Credential management
let hashedPassword: string | null = null;

export const initializeAuth = async (): Promise<void> => {
  const adminPassword = process.env.ADMIN_PASSWORD;
  const adminUsername = process.env.ADMIN_USERNAME;

  if (!adminUsername || adminUsername.trim().length === 0) {
    console.error("[AUTH] ADMIN_USERNAME not set");
    throw new Error("ADMIN_USERNAME environment variable is required");
  }

  if (!adminPassword || adminPassword.length < 8) {
    console.error(
      "[AUTH] ADMIN_PASSWORD not set or too short (minimum 8 characters)"
    );
    throw new Error(
      "ADMIN_PASSWORD environment variable is required (minimum 8 characters)"
    );
  }

  // Pre-hash the password for timing-safe comparison
  hashedPassword = await bcrypt.hash(adminPassword, BCRYPT_ROUNDS);
  console.log("[AUTH] Authentication initialized");
};

// Timing-safe credential verification
export const verifyCredentials = async (
  username: string,
  password: string
): Promise<boolean> => {
  if (!hashedPassword) {
    throw new Error("Auth not initialized");
  }

  const adminUsername = process.env.ADMIN_USERNAME!;

  // Timing-safe username comparison
  // Pad both to same length to prevent length-based timing attacks
  const maxLength = Math.max(username.length, adminUsername.length, 256);
  const userBuffer = Buffer.alloc(maxLength);
  const adminBuffer = Buffer.alloc(maxLength);
  userBuffer.write(username);
  adminBuffer.write(adminUsername);

  const usernameValid =
    crypto.timingSafeEqual(userBuffer, adminBuffer) &&
    username.length === adminUsername.length;

  // ALWAYS check password (even if username invalid) to prevent timing attacks
  const passwordValid = await bcrypt.compare(password, hashedPassword);

  // Both must be valid
  return usernameValid && passwordValid;
};

// Session management
export const createSession = (): Session => {
  const session: Session = {
    id: crypto.randomBytes(32).toString("hex"),
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_EXPIRY_MS,
  };
  sessions.set(session.id, session);
  return session;
};

export const getSession = (sessionId: string): Session | null => {
  const session = sessions.get(sessionId);
  if (!session) return null;

  // Check expiration
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
};

export const destroySession = (sessionId: string): void => {
  sessions.delete(sessionId);
};

// Cookie configuration
export const getCookieOptions = (maxAge?: number) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as const,
  maxAge: maxAge ?? SESSION_EXPIRY_MS,
  path: "/",
});

// Authentication middleware
export const requireAuth = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const sessionId = req.cookies?.[SESSION_COOKIE_NAME];

  if (!sessionId) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const session = getSession(sessionId);
  if (!session) {
    res.clearCookie(SESSION_COOKIE_NAME, getCookieOptions(0));
    res.status(401).json({ error: "Session expired" });
    return;
  }

  // Attach session to request for downstream use
  (req as any).session = session;
  next();
};

// Login rate limiting middleware
export const loginRateLimit = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const attempts = loginAttempts.get(ip);

  if (attempts) {
    if (now > attempts.resetTime) {
      // Reset after window expires
      loginAttempts.set(ip, { count: 1, resetTime: now + LOGIN_RATE_LIMIT_WINDOW });
    } else if (attempts.count >= LOGIN_MAX_ATTEMPTS) {
      const retryAfter = Math.ceil((attempts.resetTime - now) / 1000);
      res.setHeader("Retry-After", retryAfter.toString());
      res.status(429).json({
        error: "Too many login attempts",
        retryAfter,
      });
      return;
    } else {
      attempts.count++;
    }
  } else {
    loginAttempts.set(ip, { count: 1, resetTime: now + LOGIN_RATE_LIMIT_WINDOW });
  }

  next();
};

// Export constants
export { SESSION_COOKIE_NAME, SESSION_EXPIRY_MS };
