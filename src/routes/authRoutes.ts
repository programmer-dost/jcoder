import { Router } from "express";
import { signup, login, getProfile, getAlgorithms } from "../controllers/authController";
import { authenticateToken } from "../middleware/auth";

const router = Router();

/**
 * GET /algorithms
 * Get available JWT algorithms
 */
router.get("/algorithms", getAlgorithms);

/**
 * POST /signup
 * Body: { username, password, secretMessage }
 */
router.post("/signup", signup);

/**
 * POST /login
 * Body: { username, password, algorithm? }
 */
router.post("/login", login);

/**
 * GET /profile (protected)
 * Headers: { Authorization: "Bearer <token>" }
 */
router.get("/profile", authenticateToken, getProfile);

export default router;