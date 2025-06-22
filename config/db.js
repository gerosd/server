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
    password: envConfig.parsed.DB_PASSWORD,
    host: envConfig.parsed.DB_HOST,
    port: parseInt(envConfig.parsed.DB_PORT, 10),
    database: envConfig.parsed.DB_NAME,
});

export default pool;