import dotenv from 'dotenv';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import socketHandler from './sockets/socketHandler.js';

dotenv.config();

const app = express();
const server = http.createServer(app);
const configuredOrigins = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

const allowlist = new Set(configuredOrigins);
const allowOriginPatterns: RegExp[] = [
    /^http:\/\/localhost(?::\d+)?$/i,
    /^http:\/\/127\.0\.0\.1(?::\d+)?$/i,
    /^https:\/\/[a-z0-9-]+-\d+\.inc\d+\.devtunnels\.ms$/i,
    /^https:\/\/[a-z0-9-]+\.ngrok-free\.dev$/i,
    /^https:\/\/[a-z0-9-]+\.ngrok-free\.app$/i,
    /^https:\/\/[a-z0-9-]+\.loca\.lt$/i
];

const isOriginAllowed = (origin?: string): boolean => {
    if (!origin) return true;
    if (allowlist.has(origin)) return true;
    return allowOriginPatterns.some((pattern) => pattern.test(origin));
};

const io = new Server(server, {
    cors: {
        origin: (origin, callback) => {
            if (isOriginAllowed(origin)) {
                callback(null, true);
                return;
            }
            callback(new Error(`Origin not allowed by CORS: ${origin || 'unknown'}`));
        },
        credentials: true,
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'Authorization']
    }
});

// Initialize socket handler
socketHandler(io);

const PORT = Number(process.env.PORT || 3000);

server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use.`);
        console.error('Another server instance is likely already running. Stop it or change PORT in server/.env.');
        process.exit(0);
    }

    console.error('Server startup error:', err.message);
    process.exit(1);
});

server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);

    // Check Supabase connection
    void (async () => {
        try {
            const { default: supabase } = await import('./config/supabase.js');
            const { error } = await supabase.from('users').select('count', { count: 'exact', head: true });

            if (error) {
                console.error('Supabase connection failed:', error.message);
            } else {
                console.log('Connected to Supabase');
            }
        } catch (err: any) {
            console.error('Supabase connection error:', err);
        }
    })();
});

export default server;
