import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import router from './routes/user.routes.js';
import helmet from 'helmet';
// import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import {fileURLToPath} from "url";
import path from 'path';
import cookieParser from 'cookie-parser';
import {logger} from "./logs/logger.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({
    path: path.resolve(__dirname, '.env'),
});

const app = express();

app.use(helmet());

// const limiter = rateLimit({
//     windowMs: 30 * 100,
//     message: "Requests are too frequent"
// });
// app.use(limiter);

const corsOptions = {
    origin: [
        'http://localhost:5173',
    ],
    credentials: true,
    optionsSuccessStatus: 200
}

app.use(cookieParser());
app.use(cors(corsOptions));
app.use(bodyParser.json());

app.use('/api', router);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    logger.info(`Server starts on ${PORT}`);
});