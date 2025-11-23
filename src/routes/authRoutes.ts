import { Router } from "express";
import { signup, login, getAlgorithms } from "../controllers/authController";

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

export default router;