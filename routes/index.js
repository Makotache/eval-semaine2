import express from 'express'
import userRoutes from "./userRoutes.js";
import homeRoutes from "./homeRoutes.js";

const router = express.Router()

router.use('/', homeRoutes)
router.use('/user', userRoutes)

export default router