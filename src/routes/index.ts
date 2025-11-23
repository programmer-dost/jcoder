import { Router } from "express";
import authRoutes from "./authRoutes";
import userRoutes from "./userRoutes";

const router = Router();

// Mount auth routes (authentication and algorithms)
router.use("/", authRoutes);

// Mount user routes (profile and user data)
router.use("/", userRoutes);

export default router;