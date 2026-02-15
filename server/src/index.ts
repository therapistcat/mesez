import dotenv from 'dotenv';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import socketHandler from './sockets/socketHandler.js';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
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
