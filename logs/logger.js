import winston from "winston";
import DailyRotateFile from 'winston-daily-rotate-file';

export const logger = winston.createLogger({
    level: "info",
    format: winston.format.json(),
    transports: [
        new DailyRotateFile({
            filename: "logs/error-%DATE%.log",
            level: "error",
            maxSize: "20m",
            maxFiles: "14d",
            datePattern: "DD-MM-YYYY",
        }),
        new DailyRotateFile({
            filename: "logs/info-%DATE%.log",
            level: "info",
            maxSize: "20m",
            maxFiles: "14d",
            datePattern: "DD-MM-YYYY",
        }),
        new DailyRotateFile({
            filename: "logs/warn-%DATE%.log",
            level: "warn",
            maxSize: "20m",
            maxFiles: "14d",
            datePattern: "DD-MM-YYYY",
        })
    ]
})