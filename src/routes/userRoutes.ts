import { Router } from "express";
import { getSecretMessage } from "../controllers/userController";
import { authenticateToken } from "../middleware/auth";

const router = Router();

/**
 * GET /secret (protected)
 * Get user's secret message with creation time
 * Headers: { Authorization: "Bearer <token>" }
 */
router.get("/secret", authenticateToken, getSecretMessage);

export default router;