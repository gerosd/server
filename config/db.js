import { Pool } from 'pg';
import dotenv from 'dotenv';
import path from 'path';
import {fileURLToPath} from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const envConfig = dotenv.config({
    path: path.resolve(__dirname, '../db.env'),
});

const pool = new Pool({
    user: "postgres.gnkrtyzgrpmdudjqhhqg",
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
});

export default pool;
