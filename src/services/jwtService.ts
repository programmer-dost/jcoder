import { sign as hmacSign, verify as hmacVerify } from "../jwt/hmac";
import { sign as rsaSign, verify as rsaVerify } from "../jwt/rsa";
import { JwtPayload } from "../jwt/utils";
import * as fs from "fs";
import * as path from "path";

export type JwtAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';

export interface JwtSignOptions {
  algorithm: JwtAlgorithm;
  expiresIn?: string;
  issuer?: string;
}

/**
 * Validate expiration duration format
 */
export function validateExpiresIn(expiresIn: string): boolean {
  // Allow formats like: "1h", "30m", "24h", "7d", "1y", or plain numbers (seconds)
  const timeRegex = /^(\d+)([smhdy]?)$/;
  return timeRegex.test(expiresIn);
}

/**
 * Get default expiration options with descriptions
 */
export function getExpirationOptions(): { value: string; description: string }[] {
  return [
    { value: "15m", description: "15 minutes - Short session" },
    { value: "1h", description: "1 hour - Standard session" },
    { value: "24h", description: "24 hours - Extended session" },
    { value: "7d", description: "7 days - Long-term session" },
    { value: "30d", description: "30 days - Remember me" }
  ];
}

/**
 * Calculate expiration timestamp
 */
export function calculateExpirationTimestamp(expiresIn: string): Date {
  const now = new Date();
  const match = expiresIn.match(/^(\d+)([smhdy]?)$/);
  
  if (!match) {
    throw new Error("Invalid expiration format");
  }
  
  const amount = parseInt(match[1]);
  const unit = match[2] || 's'; // default to seconds
  
  switch (unit) {
    case 's': // seconds
      return new Date(now.getTime() + amount * 1000);
    case 'm': // minutes
      return new Date(now.getTime() + amount * 60 * 1000);
    case 'h': // hours
      return new Date(now.getTime() + amount * 60 * 60 * 1000);
    case 'd': // days
      return new Date(now.getTime() + amount * 24 * 60 * 60 * 1000);
    case 'y': // years
      return new Date(now.getTime() + amount * 365 * 24 * 60 * 60 * 1000);
    default:
      throw new Error(`Unsupported time unit: ${unit}`);
  }
}

export interface JwtVerifyOptions {
  algorithms?: JwtAlgorithm[];
  issuer?: string;
}

/**
 * JWT Service that supports multiple algorithms
 */
export class JwtService {
  private static getHmacSecret(): string {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET environment variable is required for HMAC algorithms");
    }
    return secret;
  }

  private static getRsaKeys(): { privateKey: string; publicKey: string } {
    try {
      const keysDir = path.join(process.cwd(), 'keys');
      const privateKey = fs.readFileSync(path.join(keysDir, 'private.pem'), 'utf8');
      const publicKey = fs.readFileSync(path.join(keysDir, 'public.pem'), 'utf8');
      return { privateKey, publicKey };
    } catch (error) {
      throw new Error("RSA keys not found. Please ensure private.pem and public.pem exist in the 'keys' directory");
    }
  }

  /**
   * Sign a JWT token with the specified algorithm
   */
  static sign(payload: JwtPayload, options: JwtSignOptions): string {
    const { algorithm, expiresIn = "24h", issuer = "jcoder-api" } = options;

    if (algorithm.startsWith('HS')) {
      // HMAC algorithms
      const secret = this.getHmacSecret();
      return hmacSign(payload, secret, {
        algorithm: algorithm as 'HS256' | 'HS384' | 'HS512',
        expiresIn,
        issuer,
      });
    } else if (algorithm.startsWith('RS')) {
      // RSA algorithms
      const { privateKey } = this.getRsaKeys();
      return rsaSign(payload, privateKey, {
        algorithm: algorithm as 'RS256' | 'RS384' | 'RS512',
        expiresIn,
        issuer,
      });
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  /**
   * Verify a JWT token with the specified algorithms
   */
  static verify(token: string, options: JwtVerifyOptions): JwtPayload {
    const { algorithms = ['HS256'], issuer = "jcoder-api" } = options;

    // Try to decode the token to get the algorithm from header
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error("Invalid token format");
    }

    const headerBase64 = parts[0];
    const headerBuffer = Buffer.from(headerBase64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const header = JSON.parse(headerBuffer.toString('utf8'));
    const tokenAlgorithm = header.alg;

    if (!algorithms.includes(tokenAlgorithm)) {
      throw new Error(`Algorithm ${tokenAlgorithm} not allowed`);
    }

    if (tokenAlgorithm.startsWith('HS')) {
      // HMAC algorithms
      const secret = this.getHmacSecret();
      return hmacVerify(token, secret, {
        algorithms: [tokenAlgorithm],
        issuer,
      });
    } else if (tokenAlgorithm.startsWith('RS')) {
      // RSA algorithms
      const { publicKey } = this.getRsaKeys();
      return rsaVerify(token, publicKey, {
        algorithms: [tokenAlgorithm],
        issuer,
      });
    } else {
      throw new Error(`Unsupported algorithm: ${tokenAlgorithm}`);
    }
  }

  /**
   * Get available algorithms based on configuration
   */
  static getAvailableAlgorithms(): JwtAlgorithm[] {
    const available: JwtAlgorithm[] = [];

    // Check HMAC availability
    if (process.env.JWT_SECRET) {
      available.push('HS256', 'HS384', 'HS512');
    }

    // Check RSA availability
    try {
      this.getRsaKeys();
      available.push('RS256', 'RS384', 'RS512');
    } catch {
      // RSA keys not available
    }

    return available;
  }
}