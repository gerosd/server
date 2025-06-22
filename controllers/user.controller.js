import pool from '../config/db.js';
import bcrypt from 'bcrypt';
import jwt from "jsonwebtoken";
import {logger} from '../logs/logger.js';

class UserController {
    async createUser(req, res) {
        try {
            const { username, password, SNL, phone, email } = req.body;

            if (!username || !password || !SNL || !phone || !email) {
                return res.status(400).send({ message: "Все поля обязательны для заполнения"});
            }

            if (password.length < 8) {
                return res.status(400).json({ message: "Длина пароля должна быть больше 7 символов" });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const newPerson = await pool.query(`INSERT INTO users (username, password_hash, "SNL", phone_number, email, role) values ($1, $2, $3, $4, $5, 'user') RETURNING *`,
                [username, hashedPassword, SNL, phone, email]);

            const {password_hash, ...userData} = newPerson.rows[0];

            const token = jwt.sign({ userId: userData.id }, process.env.JWT_SECRET, { expiresIn: '7d'});

            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 604800000,
            });

            logger.info(`Create a new user - ${username}`)

            res.json({
                ...userData,
                message: 'Пользователь успешно зарегистрирован и авторизован'
            });
        } catch (error) {
            logger.error("Ошибка входа: ", error);

            if (error.code === '23505') {
                return res.status(409).json({ message: 'Пользователь с таким именем или email уже существует' });
            }

            res.status(500).json({
                message: 'Ошибка сервера при попытке регистрации',
                error: error.message
            })
        }
    }

    async loginUser(req, res) {
        const { username, password } = req.body;

        try {
            if (!username || !password) {
                return res.status(400).json({ message: "Все поля обязательны!" })
            }

            if (password.length < 8) {
                return res.status(400).json({ message: "Длина пароля должна быть больше 7 символов" })
            }

            const user = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);

            if (user.rows.length === 0) {
                return res.status(401).json({ message: 'Неверное имя пользователя или пароль' });
            }

            const foundUser = user.rows[0];

            const isPasswordValid = await bcrypt.compare(password, foundUser.password_hash);
            if (!isPasswordValid) {
                logger.warn(`Failed login attempt - user "${username}"`);
                return res.status(401).json({ message: 'Неверное имя пользователя или пароль' });
            }

            const token = jwt.sign({ userId: foundUser.id }, process.env.JWT_SECRET, { expiresIn: '7d'});

            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 604800000,
            });

            const { password_hash, ...userData } = foundUser;
            res.json(userData);

        } catch (error) {
            logger.error('Ошибка входа: ', error);
            res.status(500).json({ message: 'Ошибка сервера при попытке входа' })
        }
    }

    async getUsers(req, res) {
        try {
            const users = await pool.query(`SELECT * FROM users`);

            logger.info("Request for all users");

            res.json(users.rows);
        } catch (error) {
            logger.error('Ошибка получения пользователей: ', error);
            res.status(500).json({ message: 'Ошибка сервера' });
        }
    }

    async getCurrentUser(req, res) {
        try {
            const user = await pool.query(`SELECT id, username, "SNL", phone_number, email FROM users WHERE id = $1`, [req.userId]);

            if (user.rows.length === 0) {
                return res.status(404).json({ message: 'Пользователь не найден' });
            }

            res.json(user.rows[0]);
        } catch (error) {
            logger.error('Ошибка получения текущего пользователя: ', error);
            res.status(500).json({ message: 'Ошибка сервера' });
        }
    }

    async updateUser(req, res) {
        try {
            const {id, username, password, SNL, phone_number, email, role} = req.body;

            let hashedPassword = null;
            if (password) {
                if (password.length < 8) {
                    return res.status(400).json({ message: "Длина пароля должна быть больше 7 символов" });
                }
                hashedPassword = await bcrypt.hash(password, 10);
            }

            const updateQuery = hashedPassword
                ? `UPDATE users set username = $1, password_hash = $2, "SNL" = $3, phone_number = $4, email = $5, role = $6 WHERE id = $7 RETURNING id, username, "SNL", phone_number, email, role`
                : `UPDATE users set username = $1, "SNL" = $2, phone_number = $3, email = $4, role = $5 WHERE id = $6 RETURNING id, username, "SNL", phone_number, email, role`;

            const params = hashedPassword
                ? [username, hashedPassword, SNL, phone_number, email, role, id]
                : [username, SNL, phone_number, email, role, id];

            const user = await pool.query(updateQuery, params);

            if (user.rows.length === 0) {
                return res.status(404).json({ message: "Пользователь не найден" });
            }

            logger.info(`User ${id} data update: ${JSON.stringify(req.body)}`);

            res.json(user.rows[0]);
        } catch (error) {
            logger.error('Ошибка обновления пользователя: ', error);

            if (error.code === '23505') {
                return res.status(409).json({ message: 'Пользователь с таким именем или email уже существует' });
            }

            res.status(500).json({ message: 'Ошибка сервера' });
        }
    }

    async deleteUser(req, res) {
        try {
            const id = req.params.id;
            const user = await pool.query(`DELETE FROM users WHERE id = $1 RETURNING id`, [id]);

            if (user.rows.length === 0) {
                return res.status(404).json({ message: 'Пользователь не найден' });
            }

            logger.info(`User ${id} has been deleted`);

            res.json({ message: 'Пользователь удален', id: user.rows[0].id });
        } catch (error) {
            logger.error("Ошибка удаления пользователя", error);
            res.status(500).json({ message: "Ошибка сервера" });
        }
    }

    async getTokenCookie(req, res) {
        const token = req.cookies.token;
        if (!token) return res.json({ isAuthenticated: false });

        try {
            jwt.verify(token, process.env.JWT_SECRET);
            res.json({ isAuthenticated: true });
        } catch (error) {
            logger.error(error);
            res.json({ isAuthenticated: false });
        }
    }

    async deleteTokenCookie(req, res) {
        try {
            res.clearCookie('token', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
            });
            res.json({ isAuthenticated: false });
        } catch (error) {
            logger.error(error);
            res.json({ isAuthenticated: true });
        }
    }
}

export default new UserController();