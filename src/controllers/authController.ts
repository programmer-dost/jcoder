import { Request, Response } from "express";
import db from "../db";
import { hashPassword, verifyPassword } from "../security/password";
import { SignupRequestBody, LoginRequestBody, UserResponse, LoginResponse, ApiResponse, User } from "../types";
import { JwtService } from "../services/jwtService";

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
  const { username, password, algorithm = 'HS256' } = req.body;

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({
      error: "username and password are required",
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

    // Generate JWT token with selected algorithm
    const token = JwtService.sign(
      { 
        userId: user.id,
        username: user.username 
      },
      {
        algorithm,
        expiresIn: "24h",
        issuer: "jcoder-api",
      }
    );

    return res.status(200).json({
      message: "Login successful",
      data: {
        user: {
          id: user.id,
          username: user.username,
          secretMessage: user.secret_message,
        },
        token,
        algorithm,
        expiresIn: "24h",
      },
    });
  } catch (err: any) {
    console.error("Error in login:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Get user profile (protected route)
 */
export const getProfile = async (req: Request, res: Response): Promise<Response> => {
  try {
    // req.user is set by the authenticateToken middleware
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get user details from database
    const user = db.prepare("SELECT id, username, secret_message, created_at FROM users WHERE id = ?")
      .get(req.user.userId) as Omit<User, 'password_hash'> | undefined;

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({
      message: "Profile retrieved successfully",
      data: {
        id: user.id,
        username: user.username,
        secretMessage: user.secret_message,
        createdAt: user.created_at,
      },
    });
  } catch (err: any) {
    console.error("Error in getProfile:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Get available JWT algorithms
 */
export const getAlgorithms = (req: Request, res: Response): Response => {
  try {
    const availableAlgorithms = JwtService.getAvailableAlgorithms();
    
    return res.status(200).json({
      message: "Available JWT algorithms",
      data: {
        algorithms: availableAlgorithms,
        default: "HS256",
        description: {
          "HS256": "HMAC using SHA-256 hash algorithm",
          "HS384": "HMAC using SHA-384 hash algorithm", 
          "HS512": "HMAC using SHA-512 hash algorithm",
          "RS256": "RSA using SHA-256 hash algorithm",
          "RS384": "RSA using SHA-384 hash algorithm",
          "RS512": "RSA using SHA-512 hash algorithm"
        }
      },
    });
  } catch (err: any) {
    console.error("Error in getAlgorithms:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};