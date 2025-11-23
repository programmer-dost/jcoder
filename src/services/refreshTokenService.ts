import * as crypto from "crypto";
import db from "../db";
import { RefreshToken } from "../types";
import { JwtService, parseExpiresIn } from "./jwtService";

/**
 * Calculate refresh token expiration based on access token duration
 * Minimum 30 minutes, otherwise 30x the access token duration
 */
export function calculateRefreshTokenExpiration(accessTokenExpiresIn: string): string {
  // Parse access token duration in seconds
  const accessTokenSeconds = parseExpiresIn(accessTokenExpiresIn);
  
  // Calculate refresh token duration (30x access token)
  const refreshTokenSeconds = accessTokenSeconds * 30;
  
  // Ensure minimum 30 minutes (1800 seconds)
  const finalSeconds = Math.max(refreshTokenSeconds, 1800);
  
  // Convert back to string format
  if (finalSeconds >= 86400) {
    // Days
    const days = Math.floor(finalSeconds / 86400);
    return `${days}d`;
  } else if (finalSeconds >= 3600) {
    // Hours
    const hours = Math.floor(finalSeconds / 3600);
    return `${hours}h`;
  } else {
    // Minutes
    const minutes = Math.floor(finalSeconds / 60);
    return `${minutes}m`;
  }
}

/**
 * Generate a JWT refresh token using separate secret
 */
export function generateRefreshToken(userId: number, username: string, accessTokenExpiresIn: string): string {
  const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
  if (!refreshTokenSecret) {
    throw new Error('REFRESH_TOKEN_SECRET environment variable is required');
  }
  
  const refreshTokenExpiration = calculateRefreshTokenExpiration(accessTokenExpiresIn);
  
  // Use HMAC with separate secret for refresh tokens
  return JwtService.signWithCustomSecret(
    {
      userId,
      username,
      type: 'refresh'
    },
    {
      algorithm: 'HS256',
      expiresIn: refreshTokenExpiration,
      issuer: "jcoder-refresh",
    },
    refreshTokenSecret
  );
}

/**
 * Hash a refresh token for secure storage
 */
export function hashRefreshToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Store refresh token in database
 */
export function storeRefreshToken(userId: number, token: string, expiresInDays: number = 30): void {
  const tokenHash = hashRefreshToken(token);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiresInDays);
  
  const stmt = db.prepare(`
    INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `);
  
  stmt.run(userId, tokenHash, expiresAt.toISOString(), new Date().toISOString());
}

/**
 * Validate and retrieve user info from refresh token
 */
export function validateRefreshToken(token: string): { userId: number; username: string } | null {
  try {
    const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
    if (!refreshTokenSecret) {
      throw new Error('REFRESH_TOKEN_SECRET environment variable is required');
    }
    
    // Verify JWT signature and expiration
    const payload = JwtService.verifyWithCustomSecret(token, refreshTokenSecret);
    
    if (payload.type !== 'refresh') {
      return null;
    }
    
    // Also check if token exists in database (for revocation support)
    const tokenHash = hashRefreshToken(token);
    const dbResult = db.prepare(`
      SELECT user_id FROM refresh_tokens 
      WHERE token_hash = ? AND expires_at > datetime('now')
    `).get(tokenHash) as { user_id: number } | undefined;
    
    if (!dbResult || dbResult.user_id !== payload.userId) {
      return null;
    }
    
    return {
      userId: payload.userId,
      username: payload.username
    };
  } catch (error) {
    return null;
  }
}

/**
 * Revoke (delete) a refresh token
 */
export function revokeRefreshToken(token: string): boolean {
  const tokenHash = hashRefreshToken(token);
  
  const result = db.prepare(`
    DELETE FROM refresh_tokens 
    WHERE token_hash = ?
  `).run(tokenHash);
  
  return result.changes > 0;
}

/**
 * Revoke all refresh tokens for a user
 */
export function revokeAllUserTokens(userId: number): number {
  const result = db.prepare(`
    DELETE FROM refresh_tokens 
    WHERE user_id = ?
  `).run(userId);
  
  return result.changes;
}

/**
 * Clean up expired refresh tokens
 */
export function cleanupExpiredTokens(): number {
  const result = db.prepare(`
    DELETE FROM refresh_tokens 
    WHERE expires_at <= datetime('now')
  `).run();
  
  return result.changes;
}

/**
 * Rotate refresh token (revoke old, create new)
 */
export function rotateRefreshToken(oldToken: string, userId: number, accessTokenExpiresIn: string = '1h'): string | null {
  const userInfo = validateRefreshToken(oldToken);
  if (!userInfo || userInfo.userId !== userId) {
    return null;
  }
  
  // Revoke old token
  revokeRefreshToken(oldToken);
  
  // Generate new token with proper expiration
  const newToken = generateRefreshToken(userId, userInfo.username, accessTokenExpiresIn);
  
  // Calculate expiration for database storage
  const refreshExpiration = calculateRefreshTokenExpiration(accessTokenExpiresIn);
  const expirationSeconds = parseExpiresIn(refreshExpiration);
  const expirationDays = Math.ceil(expirationSeconds / 86400);
  
  storeRefreshToken(userId, newToken, expirationDays);
  
  return newToken;
}