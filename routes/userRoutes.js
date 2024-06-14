import express from "express";
import auth from "../middleware/auth.js";
import { registerGet, registerPost, loginGet, loginPost, logout, dashboard } from "../controller/user.controller.js"

const router = express.Router();

router.get("/register", registerGet);
router.post("/registerPost", registerPost);
router.get("/login", loginGet);
router.post('/loginPost', loginPost);
router.get('/logout', auth, logout);
router.get('/dashboard', auth, dashboard);

export default router;