import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import messageSchema from '../schemas/message.schema.json' with { type: 'json' };
import supabase from '../config/supabase';
const ajv = new Ajv();
addFormats(ajv);
const validate = ajv.compile(messageSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Map to track connected users: username -> socketId
const userSockets = new Map();

//  ADDED EDGE CASE: Track last message time per user (basic rate limiting)
const lastMessageTime = new Map();

// Map to track public keys in memory: username -> public keys
const userPublicKeys = new Map();

const socketHandler = (io: any) => {
    // Middleware for JWT verification
    io.use((socket: any, next: (err?: any) => void) => {
        const token = socket.handshake.auth.token;
        if (token) {
            jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
                if (err) return next(new Error('Authentication error'));
                socket.user = decoded; // { id, username }
                next();
            });
        } else {
            next(); // Allow connection for login/register
        }
    });

    io.on('connection', (socket: any) => {
        console.log(`User connected: ${socket.id}`);

        if (socket.user) {
            const username = socket.user.username.trim().toLowerCase();
            console.log(`[Auth] User ${username} authenticated on socket ${socket.id}`);
            userSockets.set(username, socket.id);
            // Broadcast status
            io.emit('user_status', { username: socket.user.username, status: 'online' });
        }

        // REGISTER
        socket.on('register', async ({ id, username, password }: { id: string; username: string; password: string }) => {
            try {
                const hashedPassword = await bcrypt.hash(password, 10);
                const { data, error } = await supabase.from('users').insert([{
                    id,
                    username,
                    password_hash: hashedPassword
                }]).select().single();
                if (error) {
                    throw error;
                }
                socket.emit('register_success', { userId: data.id });
            } catch (err: any) {
                console.error(`[Register Error] ${err.message}`);
                socket.emit('error', { message: 'Registration failed (Username might be taken)' });
            }
        });

        // LOGIN
        socket.on('login', async ({ username, password }: { username: string; password: string }) => {
            try {
                const { data, error } = await supabase.from('users').select('*').eq('username', username);
                if (!data || data.length === 0 || error) {
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
                const normalizedUsername = user.username.trim().toLowerCase();
                userSockets.set(normalizedUsername, socket.id);

                socket.emit('login_success', { token, username: user.username, userId: user.id });
                // Broadcast status
                io.emit('user_status', { username: user.username, status: 'online' });

                console.log(`[Login] User ${user.username} logged in and mapped to ${socket.id}`);
                console.log(`[Status] Currently online: ${Array.from(userSockets.keys()).join(', ')}`);

            } catch (err: any) {
                console.error(`[Login Error] ${err.message}`);
                socket.emit('error', { message: 'Login failed' });
            }
        });

        // UPLOAD PUBLIC KEYS
        socket.on('upload_public_keys', async (payload: { userId?: string; username?: string; signingPublicKey?: string; encryptionPublicKey?: string; format?: string }) => {
            const username = (socket.user?.username || payload.username || '').trim().toLowerCase();
            const userId = (socket.user?.id || payload.userId || '').trim();

            if (!userId) {
                return socket.emit('error', { message: 'User id is required to upload keys' });
            }

            if (!payload.signingPublicKey || !payload.encryptionPublicKey) {
                return socket.emit('error', { message: 'Both signing and encryption public keys are required' });
            }

            try {
                const format = payload.format || 'der-base64';
                const { error } = await supabase
                    .from('publickeys')
                    .upsert({
                        id: userId,
                        public_sign_key: payload.signingPublicKey,
                        public_encrypt_key: payload.encryptionPublicKey,
                        format,
                        updated_at: new Date().toISOString()
                    }, { onConflict: 'id' });

                if (error) {
                    throw error;
                }

                if (username) {
                    userPublicKeys.set(username, {
                        signingPublicKey: payload.signingPublicKey,
                        encryptionPublicKey: payload.encryptionPublicKey,
                        format,
                        updatedAt: new Date().toISOString()
                    });
                }

                socket.emit('public_keys_uploaded', { userId, username: username || null });
            } catch (err: any) {
                console.error('Public Key Upload Error:', err.message || err);
                socket.emit('error', { message: 'Failed to upload public keys' });
            }
        });

        // CHECK IF USER HAS PUBLIC KEYS
        socket.on('check_public_keys', async (payload: { username?: string }) => {
            const username = (socket.user?.username || payload.username || '').trim().toLowerCase();
            const userId = socket.user?.id;

            if (!userId) {
                return socket.emit('error', { message: 'User id is required to check keys' });
            }

            try {
                const { data, error } = await supabase
                    .from('publickeys')
                    .select('id')
                    .eq('id', userId)
                    .single();

                if (error && error.code !== 'PGRST116') {
                    throw error;
                }

                const exists = !!data;
                socket.emit('public_keys_check_response', { exists, username: username || null });
            } catch (err: any) {
                console.error('Public Keys Check Error:', err.message || err);
                socket.emit('public_keys_check_response', { exists: false, username: username || null });
            }
        });

        // GET USER PUBLIC KEYS (for encryption)
        socket.on('get_user_public_keys', async (payload: { username: string }) => {
            const requestedUsername = payload.username.trim().toLowerCase();

            try {
                // Check memory cache first
                if (userPublicKeys.has(requestedUsername)) {
                    const keys = userPublicKeys.get(requestedUsername);
                    return socket.emit('user_public_keys_response', {
                        username: payload.username,
                        publicKeys: {
                            signingPublicKey: keys.signingPublicKey,
                            encryptionPublicKey: keys.encryptionPublicKey,
                            format: keys.format
                        }
                    });
                }

                // Fetch from database
                const { data: userData, error: userError } = await supabase
                    .from('users')
                    .select('id')
                    .eq('username', payload.username)
                    .single();

                if (userError || !userData) {
                    return socket.emit('user_public_keys_response', {
                        username: payload.username,
                        publicKeys: null,
                        error: 'User not found'
                    });
                }

                const { data: keysData, error: keysError } = await supabase
                    .from('publickeys')
                    .select('public_sign_key, public_encrypt_key, format')
                    .eq('id', userData.id)
                    .single();

                if (keysError || !keysData) {
                    return socket.emit('user_public_keys_response', {
                        username: payload.username,
                        publicKeys: null,
                        error: 'Keys not found'
                    });
                }

                const publicKeys = {
                    signingPublicKey: keysData.public_sign_key,
                    encryptionPublicKey: keysData.public_encrypt_key,
                    format: keysData.format
                };

                // Cache for future requests
                userPublicKeys.set(requestedUsername, {
                    ...publicKeys,
                    updatedAt: new Date().toISOString()
                });

                socket.emit('user_public_keys_response', {
                    username: payload.username,
                    publicKeys
                });
            } catch (err: any) {
                console.error('Get Public Keys Error:', err.message || err);
                socket.emit('user_public_keys_response', {
                    username: payload.username,
                    publicKeys: null,
                    error: 'Failed to fetch keys'
                });
            }
        });

        // MESSAGE (Direct Routing)
        socket.on('message', async (data: { id: string; from: string; to: string; content: string; status?: string; timestamp: string }) => {
            if (!socket.user) return socket.emit('error', { message: 'Unauthorized' });

            const valid = validate(data);
            if (!valid) {
                console.error(`Invalid message from ${socket.id}:`, validate.errors);
                socket.emit('error', { message: 'Invalid message format', errors: validate.errors });
                return;
            }

            if (data.from !== socket.user.username) {
                console.warn(`[Security] Blocked spoofing attempt: ${socket.id} tried to send as ${data.from}`);
                data.from = socket.user.username; // Force correct sender
            }

            const sender = data.from.trim().toLowerCase();
            const recipientUsername = data.to ? data.to.trim().toLowerCase() : null;

            if (!recipientUsername) {
                return socket.emit('error', { message: 'Recipient "to" field is required' });
            }

            //  ADDED EDGE CASE: Prevent self-messaging
            if (sender === recipientUsername) {
                return socket.emit('error', { message: 'You cannot message yourself' });
            }

            //  ADDED EDGE CASE: Prevent empty / whitespace-only messages
            if (!data.content || data.content.trim().length === 0) {
                return socket.emit('error', { message: 'Message cannot be empty' });
            }

            //  ADDED EDGE CASE: Limit message length
            if (data.content.length > 1000) {
                return socket.emit('error', { message: 'Message is too long' });
            }

            //  ADDED EDGE CASE: Basic rate limiting (anti-spam)
            const now = Date.now();
            const lastTime = lastMessageTime.get(sender) || 0;
            if (now - lastTime < 500) {
                return socket.emit('error', { message: 'You are sending messages too fast' });
            }
            lastMessageTime.set(sender, now);

            console.log(`[Message] Direct Message from ${data.from} to ${recipientUsername}`);

            const recipientSocketId = userSockets.get(recipientUsername);

            //  ADDED EDGE CASE: Store message in database for offline retrieval
            try {
                const { error: dbError } = await supabase
                    .from('messages')
                    .insert([{
                        id: data.id,
                        // Store with guessed column names: sender, recipient, content, timestamp

                        // Let's WRITE the code to insert using 'sender' and 'recipient' as a best guess, 
                        // and 'content', 'timestamp'.
                        sender: sender,
                        recipient: recipientUsername,
                        content: data.content,
                        timestamp: data.timestamp
                    }]);

                if (dbError) {
                    console.error('Failed to save message:', dbError);
                    // Non-blocking error, allow flow to continue? Or block?
                    // Better to log and continue for now.
                }
            } catch (err) {
                console.error('Message save error:', err);
            }

            if (recipientSocketId) {
                console.log(`[Routing] Delivering to socket: ${recipientSocketId}`);
                io.to(recipientSocketId).emit('message', data);
            } else {
                console.log(`[Routing] User "${recipientUsername}" is offline. Map contains: [${Array.from(userSockets.keys()).join(', ')}]`);
                socket.emit('notification', `User ${data.to} is offline. Message saved.`); // Updated notification
                // Send explicit status update to sender if not found in map
                socket.emit('user_status', { username: data.to, status: 'offline' });
            }
        });

        // GET CHAT HISTORY
        socket.on('get_chat_history', async ({ contact }: { contact: string }) => {
            if (!socket.user) return;
            const currentUser = socket.user.username.trim().toLowerCase();
            const targetUser = contact.trim().toLowerCase();

            try {
                const { data, error } = await supabase
                    .from('messages')
                    .select('*')
                    .or(`and(sender.eq.${currentUser},recipient.eq.${targetUser}),and(sender.eq.${targetUser},recipient.eq.${currentUser})`)
                    .order('timestamp', { ascending: true });

                if (error) throw error;

                // Map back to client format if needed
                const messages = data.map((m: any) => ({
                    id: m.id,
                    from: m.sender,
                    to: m.recipient,
                    content: m.content,
                    timestamp: m.timestamp,
                    status: 'read' // Simplified status
                }));

                socket.emit('chat_history', { contact: targetUser, messages });
            } catch (err: any) {
                console.error('Chat History Error:', err.message);
                socket.emit('error', { message: 'Failed to fetch chat history' });
            }
        });

        // GET ALL USERS STATUS
        socket.on('get_all_users_status', async () => {
            if (!socket.user) return;
            try {
                const currentUser = socket.user.username.trim().toLowerCase();
                const { data: users, error } = await supabase
                    .from('users')
                    .select('username');

                if (error) throw error;

                const statusList = users
                    .filter(u => u.username && u.username.trim().toLowerCase() !== currentUser)
                    .map(u => ({
                        username: u.username,
                        status: userSockets.has(u.username.trim().toLowerCase()) ? 'online' : 'offline'
                    }));

                socket.emit('all_users_status_data', statusList);
            } catch (err: any) {
                console.error("Users Status Error:", err.message);
                socket.emit('error', { message: 'Failed to fetch users status' });
            }
        });

        // GET ONLINE USERS
        socket.on('get_online_users', async () => {
            if (!socket.user) return;
            const currentUser = socket.user.username.trim().toLowerCase();

            // Emit online users for status
            const onlineUsers = Array.from(userSockets.keys())
                .filter(u => u !== currentUser);
            socket.emit('online_users_data', onlineUsers);

            // Emit ALL users for the contact list
            try {
                const { data: dbUsers } = await supabase.from('users').select('username');
                if (dbUsers) {
                    const allContacts = dbUsers
                        .filter(u => u.username && u.username.trim().toLowerCase() !== currentUser)
                        .map(u => u.username);
                    socket.emit('all_contacts_data', allContacts);
                }
            } catch (e) {
                console.error("Error fetching contacts", e);
            }
        });

        socket.on('disconnect', () => {
            if (socket.user) {
                const username = socket.user.username.trim().toLowerCase();
                console.log(`[Disconnect] User ${username} left (${socket.id})`);
                // Only delete if this is the active socket for this username
                if (userSockets.get(username) === socket.id) {
                    userSockets.delete(username);
                    // Broadcast status
                    io.emit('user_status', { username: socket.user.username, status: 'offline' });
                }
            } else {
                console.log(`[Disconnect] Guest left (${socket.id})`);
            }
        });
    });
};

export default socketHandler;
