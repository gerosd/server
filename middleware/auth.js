import jwt from 'jsonwebtoken';
import pool from "../config/db.js";
import {logger} from "../logs/logger.js";

export const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'Токен доступа отсутствует' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        logger.error('Ошибка проверки токена:', error);
        return res.status(403).json({ message: 'Недействительный токен' })
    }
}

export const requireAdmin = async (req, res, next) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({ message: 'Токен доступа отсутствует' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;

        const user = await pool.query(`SELECT role FROM users WHERE id = $1`, [req.userId]);

        if (user.rows.length === 0) {
            return res.status(404).json({ message: 'Пользователь не найден' });
        }

        if (user.rows[0].role !== 'admin') {
            return res.status(403).json({ message: 'Доступ запрещен. Требуются права администратора' });
        }

        next();
    } catch (error) {
        logger.error('Ошибка проверки прав администратора:', error);
        if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ message: 'Недействительный токен' });
        }
        res.status(500).json({ message: 'Ошибка сервера при проверке прав доступа' });
    }
}