import { Router } from 'express';
import userController from "../controllers/user.controller.js";
import {authenticateToken, requireAdmin} from "../middleware/auth.js";

const router = new Router();

//public routes
router.post('/user/register', userController.createUser);
router.post('/user/login', userController.loginUser);
router.get('/check_auth', userController.getTokenCookie);
router.delete('/logout', userController.deleteTokenCookie);

//private routes
router.get('/user/me', authenticateToken, userController.getCurrentUser);

//admin routes
router.get('/users', requireAdmin, userController.getUsers);
router.put('/user', requireAdmin, userController.updateUser);
router.delete('/user/:id', requireAdmin, userController.deleteUser);

export default router;