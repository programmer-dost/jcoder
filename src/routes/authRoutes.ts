import { Router } from "express";
import { signup, login, refreshToken, logout, logoutAll, getAlgorithms } from "../controllers/authController";
import { authenticateToken } from "../middleware/auth";

const router = Router();

/**
 * GET /algorithms
 * Get available JWT algorithms and expiration options
 */
router.get("/algorithms", getAlgorithms);

/**
 * POST /signup
 * Body: { username, password, secretMessage }
 */
router.post("/signup", signup);

/**
 * POST /login
 * Body: { username, password, algorithm?, expiresIn? }
 */
router.post("/login", login);

/**
 * POST /refresh
 * Body: { refreshToken }
 */
router.post("/refresh", refreshToken);

/**
 * POST /logout
 * Body: { refreshToken }
 */
router.post("/logout", logout);

/**
 * POST /logout-all (protected)
 * Logout from all devices
 * Headers: { Authorization: "Bearer <token>" }
 */
router.post("/logout-all", authenticateToken, logoutAll);

export default router;