const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const messageSchema = require('../schemas/message.schema.json');
const supabase= require('../config/supabase');
const ajv = new Ajv();
addFormats(ajv);
const validate = ajv.compile(messageSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Map to track connected users: username -> socketId
const userSockets = new Map();

const socketHandler = (io) => {
    // Middleware for JWT verification
    io.use((socket, next) => {
        const token = socket.handshake.auth.token;
        if (token) {
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) return next(new Error('Authentication error'));
                socket.user = decoded; // { id, username }
                next();
            });
        } else {
            next(); // Allow connection for login/register
        }
    });

    io.on('connection', (socket) => {
        console.log(`User connected: ${socket.id}`);

        if (socket.user) {
            console.log(`User authenticated as: ${socket.user.username}`);
            userSockets.set(socket.user.username, socket.id);
        }

        // REGISTER
        socket.on('register', async ({ username, password }) => {
            try {
                const hashedPassword = await bcrypt.hash(password, 10);
                const {data,error} = await supabase.from('users').insert([{
                    username,
                    password_hash: hashedPassword
                }]).select().single();
                if (error) {
                    throw error;
                }
                socket.emit('register_success', { userId: data.id });
            } catch (err) {
                console.error("Register Error:", err.message);
                socket.emit('error', { message: 'Registration failed (Username might be taken)' });
            }
        });

        // LOGIN
        socket.on('login', async ({ username, password }) => {
            try {
                const {data,error} = await supabase.from('users').select('*').eq('username', username);
                if (data.length === 0|| error) {
                    return socket.emit('error', { message: 'User not found' });
                }

                const user = data[0];
                const match = await bcrypt.compare(password, user.password_hash);

                if (!match) {
                    return socket.emit('error', { message: 'Invalid password' });
                }

                const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

                // Update socket state
                socket.user = { id: user.id, username: user.username };
                userSockets.set(user.username, socket.id);

                socket.emit('login_success', { token, username: user.username });
                console.log(`User ${user.username} logged in and mapped to ${socket.id}`);

            } catch (err) {
                console.error("Login Error:", err.message);
                socket.emit('error', { message: 'Login failed' });
            }
        });

        // MESSAGE (Direct Routing)
        socket.on('message', (data) => {
            if (!socket.user) return socket.emit('error', { message: 'Unauthorized' });

            const valid = validate(data);
            if (!valid) {
                console.error(`Invalid message from ${socket.id}:`, validate.errors);
                socket.emit('error', { message: 'Invalid message format', errors: validate.errors });
                return;
            }

            if (data.from !== socket.user.username) {
                return socket.emit('error', { message: 'Sender mismatch spoofing detected' });
            }

            const recipientUsername = data.to;

            if (!recipientUsername) {
                return socket.emit('error', { message: 'Recipient "to" field is required' });
            }

            console.log(`Direct Message from ${data.from} to ${recipientUsername}`);

            const recipientSocketId = userSockets.get(recipientUsername);

            if (recipientSocketId) {
                io.to(recipientSocketId).emit('message', data);
            } else {
                console.log(`User ${recipientUsername} is offline.`);
                socket.emit('notification', `User ${recipientUsername} is offline.`);
            }
        });

        socket.on('disconnect', () => {
            if (socket.user) {
                console.log(`User disconnected: ${socket.user.username}`);
                userSockets.delete(socket.user.username);
            } else {
                console.log(`User disconnected: ${socket.id}`);
            }
        });
    });
};

module.exports = socketHandler;
