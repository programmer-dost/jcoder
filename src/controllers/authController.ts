import { Request, Response } from "express";
import db from "../db";
import { hashPassword, verifyPassword } from "../security/password";
import { SignupRequestBody, LoginRequestBody, UserResponse, LoginResponse, ApiResponse, User } from "../types";
import { JwtService, validateExpiresIn, calculateExpirationTimestamp, getExpirationOptions } from "../services/jwtService";

/**
 * Handle user signup
 */
export const signup = async (req: Request<{}, ApiResponse<UserResponse>, SignupRequestBody>, res: Response): Promise<Response> => {
  const { username, password, secretMessage } = req.body;

  // Basic validation
  if (!username || !password || !secretMessage) {
    return res.status(400).json({
      error: "username, password and secretMessage are required",
    });
  }

  try {
    // Check if user already exists
    const existingUser = db.prepare("SELECT username FROM users WHERE username = ?").get(username);
    
    if (existingUser) {
      return res.status(409).json({ error: "Username already taken" });
    }

    // Hash the password
    const passwordHash = await hashPassword(password);
    const createdAt = new Date().toISOString();

    const stmt = db.prepare(
      `
      INSERT INTO users (username, password_hash, secret_message, created_at)
      VALUES (@username, @password_hash, @secret_message, @created_at)
      `
    );

    stmt.run({
      username,
      password_hash: passwordHash,
      secret_message: secretMessage,
      created_at: createdAt,
    });

    return res.status(201).json({
      message: "User created successfully",
      data: {
        username,
        secretMessage,
        createdAt,
      },
    });
  } catch (err: any) {
    console.error("Error in signup:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Handle user login
 */
export const login = async (req: Request<{}, ApiResponse<LoginResponse>, LoginRequestBody>, res: Response): Promise<Response> => {
  const { username, password, algorithm = 'HS256', expiresIn = '24h' } = req.body;

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({
      error: "username and password are required",
    });
  }

  // Validate expiration duration format
  if (!validateExpiresIn(expiresIn)) {
    return res.status(400).json({
      error: "Invalid expiration format. Use formats like: '15m', '1h', '24h', '7d', '30d' or plain numbers (seconds)",
    });
  }

  try {
    // Check if the requested algorithm is available
    const availableAlgorithms = JwtService.getAvailableAlgorithms();
    if (!availableAlgorithms.includes(algorithm)) {
      return res.status(400).json({
        error: `Algorithm '${algorithm}' is not available. Available algorithms: ${availableAlgorithms.join(', ')}`,
      });
    }

    // Find user by username
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as User | undefined;
    
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.password_hash);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Calculate expiration timestamp
    const issuedAt = new Date();
    const expiresAt = calculateExpirationTimestamp(expiresIn);

    // Generate JWT token with selected algorithm and expiration
    const token = JwtService.sign(
      { 
        userId: user.id,
        username: user.username 
      },
      {
        algorithm,
        expiresIn,
        issuer: "jcoder-api",
      }
    );

    return res.status(200).json({
      message: "Login successful",
      data: {
        user: {
          id: user.id,
          username: user.username,
        },
        token,
        algorithm,
        expiresIn,
        issuedAt: issuedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
      },
    });
  } catch (err: any) {
    console.error("Error in login:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Get available JWT algorithms and expiration options
 */
export const getAlgorithms = (req: Request, res: Response): Response => {
  try {
    const availableAlgorithms = JwtService.getAvailableAlgorithms();
    const expirationOptions = getExpirationOptions();
    
    return res.status(200).json({
      message: "Available JWT algorithms and expiration options",
      data: {
        algorithms: availableAlgorithms,
        defaultAlgorithm: "HS256",
        algorithmDescriptions: {
          "HS256": "HMAC using SHA-256 hash algorithm",
          "HS384": "HMAC using SHA-384 hash algorithm", 
          "HS512": "HMAC using SHA-512 hash algorithm",
          "RS256": "RSA using SHA-256 hash algorithm",
          "RS384": "RSA using SHA-384 hash algorithm",
          "RS512": "RSA using SHA-512 hash algorithm"
        },
        expirationOptions,
        defaultExpiration: "24h",
        expirationFormats: {
          "examples": ["15m", "1h", "24h", "7d", "30d"],
          "units": {
            "s": "seconds",
            "m": "minutes", 
            "h": "hours",
            "d": "days",
            "y": "years"
          },
          "note": "Use format: number + unit (e.g., '2h' for 2 hours) or plain numbers for seconds"
        }
      },
    });
  } catch (err: any) {
    console.error("Error in getAlgorithms:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};