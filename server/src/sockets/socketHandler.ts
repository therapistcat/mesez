import { createHash } from 'node:crypto';
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

const MAX_TOTAL_FRAGMENTS = 500;
const MAX_FRAGMENT_PAYLOAD_BYTES = 31;
const FRAGMENT_WINDOW_MS = 30_000;
const FRAGMENT_RATE_LIMIT_PER_SECOND = 250;
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

interface AuthUser {
    id: string;
    username: string;
}

interface PublicKeysCacheEntry {
    signingPublicKey: string;
    encryptionPublicKey: string;
    format: string;
    updatedAt: string;
}

interface DirectMessage {
    id: string;
    from: string;
    to: string;
    content: string;
    timestamp: string;
    status?: 'sent' | 'delivered' | 'read';
    encrypted?: boolean;
    iv?: string;
    content_type?: 'text' | 'image' | 'file';
    transport?: 'internet' | 'bluetooth';
}

interface FragmentPacket {
    msg_id: string;
    frag_id: number;
    total_frags: number;
    checksum: string;
    payload: string;
    to: string;
}

interface FragmentState {
    fragments: Map<number, string>;
    total_frags: number;
    checksum: string;
    senderSocketId: string;
    to: string;
    timestamp: number;
}

interface FragmentRateWindow {
    windowStart: number;
    count: number;
}

// Map to track connected users: normalized username -> socketId.
const userSockets = new Map<string, string>();

// Track last direct message timestamp per sender.
const lastMessageTime = new Map<string, number>();

// Map to track public keys in memory: normalized username -> public keys.
const userPublicKeys = new Map<string, PublicKeysCacheEntry>();

// Message fragment state: msg_id -> incomplete payload state.
const fragmentBuffer = new Map<string, FragmentState>();

// Per-socket fragment rate limiter.
const fragmentRateWindows = new Map<string, FragmentRateWindow>();
let isFragmentCleanupStarted = false;

const normalizeUsername = (value: string): string => value.trim().toLowerCase();
const checksumRegex = /^[a-f0-9]{64}$/i;

const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

const cleanupExpiredFragments = (): void => {
    const now = Date.now();
    for (const [msgId, state] of fragmentBuffer.entries()) {
        if (now - state.timestamp > FRAGMENT_WINDOW_MS) {
            fragmentBuffer.delete(msgId);
        }
    }
};

const enforceFragmentRateLimit = (socketId: string): boolean => {
    const now = Date.now();
    const current = fragmentRateWindows.get(socketId);

    if (!current || now - current.windowStart >= 1000) {
        fragmentRateWindows.set(socketId, { windowStart: now, count: 1 });
        return true;
    }

    if (current.count >= FRAGMENT_RATE_LIMIT_PER_SECOND) {
        return false;
    }

    current.count += 1;
    return true;
};

const isValidFragment = (fragment: unknown): fragment is FragmentPacket => {
    if (!fragment || typeof fragment !== 'object') {
        return false;
    }

    const candidate = fragment as FragmentPacket;
    if (typeof candidate.msg_id !== 'string' || candidate.msg_id.trim().length === 0) {
        return false;
    }
    if (!uuidRegex.test(candidate.msg_id)) {
        return false;
    }

    if (!Number.isInteger(candidate.frag_id) || candidate.frag_id < 0) {
        return false;
    }

    if (!Number.isInteger(candidate.total_frags) || candidate.total_frags < 1 || candidate.total_frags > MAX_TOTAL_FRAGMENTS) {
        return false;
    }

    if (candidate.frag_id >= candidate.total_frags) {
        return false;
    }

    if (typeof candidate.payload !== 'string') {
        return false;
    }

    if (Buffer.byteLength(candidate.payload, 'utf8') > MAX_FRAGMENT_PAYLOAD_BYTES) {
        return false;
    }

    if (typeof candidate.checksum !== 'string' || !checksumRegex.test(candidate.checksum)) {
        return false;
    }

    if (typeof candidate.to !== 'string' || candidate.to.trim().length === 0) {
        return false;
    }

    return true;
};

const processDirectMessage = async (io: any, socket: any, rawData: unknown): Promise<void> => {
    if (!socket.user) {
        socket.emit('error', { message: 'Unauthorized' });
        return;
    }

    if (!rawData || typeof rawData !== 'object') {
        socket.emit('error', { message: 'Invalid message payload' });
        return;
    }

    const message = rawData as Partial<DirectMessage> & { sender?: string };

    // Allow sender alias while preserving AJV contract (`from`) for validation.
    if (typeof message.from !== 'string' && typeof message.sender === 'string') {
        message.from = message.sender;
    }

    const valid = validate(message);
    if (!valid) {
        socket.emit('error', { message: 'Invalid message format', errors: validate.errors });
        return;
    }

    const authUsername = normalizeUsername((socket.user as AuthUser).username);
    const claimedSender = normalizeUsername(message.from!);

    // Security check: authenticated socket user must match sender in payload.
    if (authUsername !== claimedSender) {
        socket.emit('error', { message: 'Sender mismatch for authenticated user' });
        return;
    }

    const recipientRaw = message.to!.trim();
    const recipientUsername = normalizeUsername(recipientRaw);

    if (!recipientUsername) {
        socket.emit('error', { message: 'Recipient "to" field is required' });
        return;
    }

    if (recipientUsername === authUsername) {
        socket.emit('error', { message: 'You cannot message yourself' });
        return;
    }

    const content = message.content!;
    if (content.trim().length === 0) {
        socket.emit('error', { message: 'Message cannot be empty' });
        return;
    }

    if (content.length > 1000) {
        socket.emit('error', { message: 'Message is too long' });
        return;
    }

    // Basic anti-spam rate limit for completed direct messages.
    const now = Date.now();
    const senderLastMessage = lastMessageTime.get(authUsername) || 0;
    if (now - senderLastMessage < 500) {
        socket.emit('error', { message: 'You are sending messages too fast' });
        return;
    }
    lastMessageTime.set(authUsername, now);

    const outboundMessage: DirectMessage = {
        id: message.id!,
        from: (socket.user as AuthUser).username,
        to: recipientRaw,
        content,
        timestamp: message.timestamp!
    };

    if (message.status) {
        outboundMessage.status = message.status;
    }
    if (typeof message.encrypted === 'boolean') {
        outboundMessage.encrypted = message.encrypted;
    }
    if (typeof message.iv === 'string') {
        outboundMessage.iv = message.iv;
    }
    if (message.content_type) {
        outboundMessage.content_type = message.content_type;
    }
    if (message.transport) {
        outboundMessage.transport = message.transport;
    }

    try {
        const { error: dbError } = await supabase
            .from('messages')
            .insert([{
                id: outboundMessage.id,
                sender_username: authUsername,
                recipient_username: recipientUsername,
                content: outboundMessage.content,
                status: outboundMessage.status ?? 'sent',
                timestamp: outboundMessage.timestamp
            }]);

        if (dbError) {
            throw dbError;
        }
    } catch (err: any) {
        console.error('Failed to save message:', err?.message || err);
        socket.emit('error', { message: 'Failed to persist message' });
        return;
    }

    const recipientSocketId = userSockets.get(recipientUsername);
    if (recipientSocketId) {
        io.to(recipientSocketId).emit('direct_message', outboundMessage);
    } else {
        socket.emit('notification', `User ${recipientRaw} is offline. Message saved.`);
        socket.emit('user_status', { username: recipientRaw, status: 'offline' });
    }
};

const socketHandler = (io: any) => {
    // Middleware for JWT verification.
    io.use((socket: any, next: (err?: Error) => void) => {
        const token = socket.handshake.auth.token;
        if (token) {
            jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
                if (err) {
                    return next(new Error('Authentication error'));
                }
                socket.user = decoded as AuthUser;
                next();
            });
        } else {
            next();
        }
    });

    // Periodic cleanup prevents stale fragment buffers from leaking memory.
    if (!isFragmentCleanupStarted) {
        setInterval(cleanupExpiredFragments, 5_000);
        isFragmentCleanupStarted = true;
    }

    io.on('connection', (socket: any) => {
        console.log(`User connected: ${socket.id}`);

        if (socket.user) {
            const username = normalizeUsername((socket.user as AuthUser).username);
            userSockets.set(username, socket.id);
            io.emit('user_status', { username: (socket.user as AuthUser).username, status: 'online' });
        }

        socket.on('register', async ({ id, username, password }: { id: string; username: string; password: string }) => {
            try {
                const hashedPassword = await bcrypt.hash(password, 10);
                const { data, error } = await supabase
                    .from('users')
                    .insert([{ id, username, password_hash: hashedPassword }])
                    .select()
                    .single();

                if (error) {
                    throw error;
                }

                socket.emit('register_success', { userId: data.id });
            } catch (err: any) {
                console.error(`[Register Error] ${err.message}`);
                socket.emit('error', { message: 'Registration failed (Username might be taken)' });
            }
        });

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

                socket.user = { id: user.id, username: user.username } as AuthUser;
                userSockets.set(normalizeUsername(user.username), socket.id);

                socket.emit('login_success', { token, username: user.username, userId: user.id });
                io.emit('user_status', { username: user.username, status: 'online' });
            } catch (err: any) {
                console.error(`[Login Error] ${err.message}`);
                socket.emit('error', { message: 'Login failed' });
            }
        });

        socket.on('upload_public_keys', async (payload: { userId?: string; username?: string; signingPublicKey?: string; encryptionPublicKey?: string; format?: string }) => {
            const username = normalizeUsername((socket.user?.username || payload.username || '').trim());
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

        socket.on('check_public_keys', async (payload: { username?: string }) => {
            const username = normalizeUsername((socket.user?.username || payload.username || '').trim());
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

                socket.emit('public_keys_check_response', { exists: !!data, username: username || null });
            } catch (err: any) {
                console.error('Public Keys Check Error:', err.message || err);
                socket.emit('public_keys_check_response', { exists: false, username: username || null });
            }
        });

        socket.on('get_user_public_keys', async (payload: { username: string }) => {
            const requestedUsername = normalizeUsername(payload.username || '');

            if (!requestedUsername) {
                return socket.emit('user_public_keys_response', {
                    username: payload.username,
                    publicKeys: null,
                    error: 'Username is required'
                });
            }

            try {
                if (userPublicKeys.has(requestedUsername)) {
                    const keys = userPublicKeys.get(requestedUsername)!;
                    return socket.emit('user_public_keys_response', {
                        username: payload.username,
                        publicKeys: {
                            signingPublicKey: keys.signingPublicKey,
                            encryptionPublicKey: keys.encryptionPublicKey,
                            format: keys.format
                        }
                    });
                }

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

        // Legacy direct message event support (non-fragmented clients).
        socket.on('message', async (data: unknown) => {
            await processDirectMessage(io, socket, data);
        });

        socket.on('fragment', async (fragment: unknown) => {
            cleanupExpiredFragments();

            if (!socket.user) {
                socket.emit('error', { message: 'Unauthorized' });
                return;
            }

            if (!enforceFragmentRateLimit(socket.id)) {
                socket.emit('error', { message: 'Fragment rate limit exceeded' });
                return;
            }

            if (!isValidFragment(fragment)) {
                socket.emit('error', { message: 'Invalid fragment format' });
                return;
            }

            const packet = fragment as FragmentPacket;
            const msgId = packet.msg_id;
            const normalizedChecksum = packet.checksum.toLowerCase();

            let state = fragmentBuffer.get(msgId);
            if (!state) {
                state = {
                    fragments: new Map<number, string>(),
                    total_frags: packet.total_frags,
                    checksum: normalizedChecksum,
                    senderSocketId: socket.id,
                    to: packet.to,
                    timestamp: Date.now()
                };
                fragmentBuffer.set(msgId, state);
            } else {
                // Every fragment of one message must come from same socket + metadata.
                if (state.senderSocketId !== socket.id) {
                    socket.emit('error', { message: 'Fragment sender mismatch' });
                    return;
                }

                if (state.total_frags !== packet.total_frags || state.checksum !== normalizedChecksum || state.to !== packet.to) {
                    fragmentBuffer.delete(msgId);
                    socket.emit('error', { message: 'Fragment metadata mismatch' });
                    return;
                }
            }

            // Duplicate fragments are ignored by design.
            if (state.fragments.has(packet.frag_id)) {
                return;
            }

            state.fragments.set(packet.frag_id, packet.payload);
            state.timestamp = Date.now();

            if (state.fragments.size !== state.total_frags) {
                return;
            }

            try {
                const orderedParts: string[] = [];
                for (let i = 0; i < state.total_frags; i += 1) {
                    const payload = state.fragments.get(i);
                    if (payload === undefined) {
                        socket.emit('error', { message: 'Missing fragment during reassembly' });
                        return;
                    }
                    orderedParts.push(payload);
                }

                const assembled = orderedParts.join('');
                const assembledChecksum = sha256Hex(assembled).toLowerCase();

                if (assembledChecksum !== state.checksum) {
                    socket.emit('error', { message: 'Fragment checksum verification failed' });
                    return;
                }

                let parsedMessage: unknown;
                try {
                    parsedMessage = JSON.parse(assembled);
                } catch {
                    socket.emit('error', { message: 'Failed to parse reassembled message' });
                    return;
                }

                const parsedTo = (parsedMessage as { to?: string })?.to;
                if (typeof parsedTo !== 'string' || normalizeUsername(parsedTo) !== normalizeUsername(state.to)) {
                    socket.emit('error', { message: 'Fragment recipient mismatch' });
                    return;
                }

                await processDirectMessage(io, socket, parsedMessage);
            } finally {
                // Always clear full-message buffer once processing is complete/failed.
                fragmentBuffer.delete(msgId);
            }
        });

        socket.on('get_chat_history', async ({ contact }: { contact: string }) => {
            if (!socket.user) {
                return;
            }

            const currentUser = normalizeUsername(socket.user.username);
            const targetUser = normalizeUsername(contact || '');

            try {
                const { data, error } = await supabase
                    .from('messages')
                    .select('*')
                    .or(`and(sender_username.eq.${currentUser},recipient_username.eq.${targetUser}),and(sender_username.eq.${targetUser},recipient_username.eq.${currentUser})`)
                    .order('timestamp', { ascending: true });

                if (error) {
                    throw error;
                }

                const messages = (data || []).map((m: any) => ({
                    id: m.id,
                    from: m.sender_username,
                    to: m.recipient_username,
                    content: m.content,
                    timestamp: m.timestamp,
                    status: m.status ?? 'read'
                }));

                socket.emit('chat_history', { contact: targetUser, messages });
            } catch (err: any) {
                console.error('Chat History Error:', err.message);
                socket.emit('error', { message: 'Failed to fetch chat history' });
            }
        });

        socket.on('get_all_users_status', async () => {
            if (!socket.user) {
                return;
            }

            try {
                const currentUser = normalizeUsername(socket.user.username);
                const { data: users, error } = await supabase.from('users').select('username');

                if (error) {
                    throw error;
                }

                const statusList = (users || [])
                    .filter((u: any) => u.username && normalizeUsername(u.username) !== currentUser)
                    .map((u: any) => ({
                        username: u.username,
                        status: userSockets.has(normalizeUsername(u.username)) ? 'online' : 'offline'
                    }));

                socket.emit('all_users_status_data', statusList);
            } catch (err: any) {
                console.error('Users Status Error:', err.message);
                socket.emit('error', { message: 'Failed to fetch users status' });
            }
        });

        socket.on('get_online_users', async () => {
            if (!socket.user) {
                return;
            }

            const currentUser = normalizeUsername(socket.user.username);
            const onlineUsers = Array.from(userSockets.keys()).filter((u) => u !== currentUser);
            socket.emit('online_users_data', onlineUsers);

            try {
                const { data: dbUsers } = await supabase.from('users').select('username');
                if (dbUsers) {
                    const allContacts = dbUsers
                        .filter((u: any) => u.username && normalizeUsername(u.username) !== currentUser)
                        .map((u: any) => u.username);
                    socket.emit('all_contacts_data', allContacts);
                }
            } catch (err) {
                console.error('Error fetching contacts', err);
            }
        });

        socket.on('disconnect', () => {
            if (socket.user) {
                const username = normalizeUsername(socket.user.username);
                if (userSockets.get(username) === socket.id) {
                    userSockets.delete(username);
                    io.emit('user_status', { username: socket.user.username, status: 'offline' });
                }
            }

            // Drop in-flight fragment buffers for disconnected sender to prevent leaks.
            for (const [msgId, state] of fragmentBuffer.entries()) {
                if (state.senderSocketId === socket.id) {
                    fragmentBuffer.delete(msgId);
                }
            }

            fragmentRateWindows.delete(socket.id);
        });
    });
};

export default socketHandler;
