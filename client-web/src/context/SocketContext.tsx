import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import type { ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';
import { v4 as uuidv4 } from 'uuid';
import { generateAndStoreKeys, loadStoredKeys, saveMessageLocally, loadLocalHistory, loadLocalInbox, normalizeUsername } from '../../crypto/keyManagerBrowser';
import { encryptMessage, decryptMessage } from '../../crypto/messageEncryption';
import { fragmentMessage } from '../utils/FragmentChopper';

interface User {
    id: string;
    username: string;
}

export interface Message {
    id: string;
    from: string;
    to: string;
    content: string;
    timestamp: string;
    status?: string;
    encrypted?: boolean;
    iv?: string;
    sender_encryption_public_key?: string;
}

export interface InboxItem {
    contact: string;
    last_message_preview: string;
    last_timestamp: string;
    unread_count: number;
}

interface SocketContextType {
    socket: Socket | null;
    user: User | null;
    isConnected: boolean;
    login: (username: string, password: string) => Promise<void>;
    register: (username: string, password: string) => Promise<void>;
    logout: () => void;
    sendMessage: (to: string, content: string) => void;
    messages: Message[];
    setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
    inbox: InboxItem[];
    loadInbox: () => void;
    loadChatHistory: (contact: string) => void;
    onlineUsers: string[];
    allContacts: string[];
}

const SocketContext = createContext<SocketContextType | undefined>(undefined);

export const useSocket = () => {
    const context = useContext(SocketContext);
    if (!context) {
        throw new Error('useSocket must be used within a SocketProvider');
    }
    return context;
};

const SERVER_URL = (import.meta.env.VITE_SERVER_URL as string) || 'http://localhost:3000';

// Map server message format to client format
function mapServerMessage(msg: any): Message {
    return {
        id: msg.id,
        from: msg.sender_username || msg.sender || msg.from,
        to: msg.recipient_username || msg.recipient || msg.to,
        content: msg.content,
        timestamp: msg.timestamp,
        status: msg.status,
        encrypted: msg.encrypted,
        iv: msg.iv,
        sender_encryption_public_key: msg.sender_encryption_public_key,
    };
}

export const SocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [socket, setSocket] = useState<Socket | null>(null);
    const [user, setUser] = useState<User | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [messages, setMessages] = useState<Message[]>([]);
    const [inbox, setInbox] = useState<InboxItem[]>([]);
    const [onlineUsers, setOnlineUsers] = useState<string[]>([]);
    const [allContacts, setAllContacts] = useState<string[]>([]);

    const loadInbox = useCallback(async () => {
        if (!user) {
            setInbox([]);
            return;
        }

        const localInbox = await loadLocalInbox(user.username);
        setInbox(localInbox);
    }, [user]);

    const loadChatHistory = useCallback(async (contact: string) => {
        if (!user) return;
        const history = await loadLocalHistory(user.username, contact);
        
        // Decrypt any encrypted messages in the history
        const decryptedHistory = await Promise.all(
            history.map(async (msg) => {
                // Only attempt decryption if message is marked as encrypted and has iv and content
                if (msg.encrypted && msg.iv && msg.content && typeof msg.content === 'string') {
                    // Skip if content is already an error message
                    if (msg.content.startsWith('[Encrypted message')) {
                        return msg;
                    }
                    
                    // Check if content looks like base64 (encrypted data)
                    if (!/^[A-Za-z0-9+/=]+$/.test(msg.content)) {
                        return msg; // Not base64, probably already decrypted or invalid
                    }
                    
                    try {
                        const myKeys = await loadStoredKeys(user.username);
                        if (myKeys) {
                            let senderEncryptionPublicKey = msg.sender_encryption_public_key;
                            
                            // If no public key in message, try to request it
                            if (!senderEncryptionPublicKey && socket) {
                                // Use inline request instead of useCallback to avoid dependency issues
                                const senderKeys = await new Promise<any>((resolve) => {
                                    let settled = false;
                                    let timer: ReturnType<typeof setTimeout>;

                                    const cleanup = () => {
                                        clearTimeout(timer);
                                        socket.off('user_public_keys_response', onKeys);
                                    };

                                    const onKeys = (data: any) => {
                                        const responseUsername = normalizeUsername(data?.username || '');
                                        const senderUsername = normalizeUsername(msg.from || '');
                                        if (!responseUsername || !senderUsername || responseUsername !== senderUsername) {
                                            return;
                                        }
                                        settled = true;
                                        cleanup();
                                        resolve(data);
                                    };

                                    timer = setTimeout(() => {
                                        if (settled) return;
                                        cleanup();
                                        resolve(null);
                                    }, 3000);

                                    socket.on('user_public_keys_response', onKeys);
                                    socket.emit('get_user_public_keys', { username: msg.from });
                                });
                                senderEncryptionPublicKey = senderKeys?.publicKeys?.encryptionPublicKey;
                            }
                            
                            if (senderEncryptionPublicKey) {
                                const decrypted = await decryptMessage(
                                    msg.content,
                                    msg.iv,
                                    senderEncryptionPublicKey,
                                    myKeys.encryption.privateKey
                                );
                                console.log('[Chat History] Successfully decrypted old message');
                                // Return decrypted message without encryption metadata
                                return { 
                                    ...msg, 
                                    content: decrypted,
                                    encrypted: false,
                                    iv: undefined,
                                    sender_encryption_public_key: undefined
                                };
                            }
                        }
                    } catch (err) {
                        console.warn('[Chat History Decryption] Failed to decrypt message:', err);
                    }
                }
                return msg;
            })
        );
        
        setMessages(decryptedHistory);
    }, [user, socket]);

    const requestUserPublicKeys = useCallback((username: string, timeoutMs = 5000) => {
        return new Promise<any>((resolve) => {
            if (!socket) {
                resolve(null);
                return;
            }

            const requestedUsername = normalizeUsername(username);
            if (!requestedUsername) {
                resolve(null);
                return;
            }

            let settled = false;
            let timer: ReturnType<typeof setTimeout>;

            const cleanup = () => {
                clearTimeout(timer);
                socket.off('user_public_keys_response', onKeys);
            };

            const onKeys = (data: any) => {
                const responseUsername = normalizeUsername(data?.username || '');
                if (!responseUsername || responseUsername !== requestedUsername) {
                    return;
                }

                settled = true;
                cleanup();
                resolve(data);
            };

            timer = setTimeout(() => {
                if (settled) return;
                cleanup();
                resolve(null);
            }, timeoutMs);

            socket.on('user_public_keys_response', onKeys);
            socket.emit('get_user_public_keys', { username: requestedUsername });
        });
    }, [socket]);

    const syncOwnKeysWithServer = useCallback(async (username: string): Promise<void> => {
        if (!socket) return;

        const normalizedUsername = normalizeUsername(username);
        if (!normalizedUsername) return;

        let localKeys = await loadStoredKeys(normalizedUsername);

        if (!localKeys) {
            const generated = await generateAndStoreKeys(normalizedUsername);
            socket.emit('upload_public_keys', {
                username: normalizedUsername,
                signingPublicKey: generated.signingPublicKey,
                encryptionPublicKey: generated.encryptionPublicKey,
                format: generated.format,
            });
            return;
        }

        const serverKeysResponse = await requestUserPublicKeys(normalizedUsername, 5000);
        const serverKeys = serverKeysResponse?.publicKeys;

        if (!serverKeys) {
            socket.emit('upload_public_keys', {
                username: normalizedUsername,
                signingPublicKey: localKeys.signing.publicKey,
                encryptionPublicKey: localKeys.encryption.publicKey,
                format: localKeys.format,
            });
            return;
        }

        const signingMatches = serverKeys.signingPublicKey === localKeys.signing.publicKey;
        const encryptionMatches = serverKeys.encryptionPublicKey === localKeys.encryption.publicKey;

        if (!signingMatches || !encryptionMatches) {
            console.warn('[Key Sync] Local/server key mismatch detected. Uploading local keys to restore decrypt compatibility.');
            socket.emit('upload_public_keys', {
                username: normalizedUsername,
                signingPublicKey: localKeys.signing.publicKey,
                encryptionPublicKey: localKeys.encryption.publicKey,
                format: localKeys.format,
            });
        }
    }, [socket, requestUserPublicKeys]);

    useEffect(() => {
        const newSocket = io(SERVER_URL, {
            autoConnect: false,
        });

        setSocket(newSocket);

        newSocket.on('connect', () => {
            setIsConnected(true);
            console.log('✅ Connected to server');
            newSocket.emit('get_online_users'); // Fetch online and all contacts
        });

        newSocket.on('disconnect', () => {
            setIsConnected(false);
            console.log('❌ Disconnected from server');
        });

        newSocket.on('connect_error', (err: any) => {
            console.error('Connection error:', err.message);
        });

        newSocket.on('error', (err: any) => {
            console.error('Socket error:', err);
        });

        newSocket.on('chat_history', async () => {
            // In the new model, we rely on local history + sync of pending.
            // We keep this event empty or use it as a trigger if needed, 
            // but we don't fetch full history from server anymore.
        });

        newSocket.on('inbox_data', (data: InboxItem[]) => {
            setInbox(data);
        });

        newSocket.on('online_users_data', (data: string[]) => {
            setOnlineUsers(data);
        });

        newSocket.on('all_contacts_data', (data: string[]) => {
            setAllContacts(data);
        });

        newSocket.on('user_status', (_data: { username: string; status: string }) => {
            // Refresh online users when someone's status changes
            newSocket.emit('get_online_users');
        });

        // Attempt to recover session from localStorage
        const savedToken = localStorage.getItem('mesez_token');
        const savedUsername = localStorage.getItem('mesez_username');
        if (savedToken && savedUsername) {
            newSocket.auth = { token: savedToken };
            newSocket.connect();
            setUser({ id: 'recovered', username: savedUsername });

            // Check if we have keys locally. If not, generate them (user cleared data or new browser).
            loadStoredKeys(savedUsername).then(async () => {
                try {
                    await syncOwnKeysWithServer(savedUsername);
                } catch (e) {
                    console.error('Failed key sync during recovery:', e);
                }
            });
        } else {
            newSocket.connect();
        }

        return () => {
            newSocket.off('connect');
            newSocket.off('disconnect');
            newSocket.off('connect_error');
            newSocket.off('error');
            // newSocket.off('direct_message'); // Moved to separate effect
            // newSocket.off('message'); // Moved to separate effect
            newSocket.off('chat_history');
            newSocket.off('inbox_data');
            newSocket.off('online_users_data');
            newSocket.off('all_contacts_data');
            newSocket.off('user_status');
            newSocket.close();
        };
    }, []);

    // Effect for handling incoming messages with access to current user state
    useEffect(() => {
        if (!socket || !user) return;

        const onDirectMessage = async (msg: any) => {
            console.log('[Socket] Received message raw:', msg);
            const mapped = mapServerMessage(msg);

            // Decrypt message if encrypted
            if (mapped.encrypted && mapped.iv) {
                console.log('[Decryption] Message is encrypted. Attempting to decrypt...');
                try {
                    const myKeys = await loadStoredKeys(user.username);
                    if (!myKeys) {
                        console.error('[Decryption] Local keys not found for user:', user.username);
                    } else {
                        const senderPublicKeyFromPayload = typeof mapped.sender_encryption_public_key === 'string'
                            ? mapped.sender_encryption_public_key
                            : '';

                        let senderEncryptionPublicKey = senderPublicKeyFromPayload;

                        if (!senderEncryptionPublicKey) {
                            console.log('[Decryption] Local keys found. Fetching public key for sender:', mapped.from);
                            const senderKeys = await requestUserPublicKeys(mapped.from, 5000);
                            senderEncryptionPublicKey = senderKeys?.publicKeys?.encryptionPublicKey || '';
                        }

                        if (senderEncryptionPublicKey) {
                            console.log('[Decryption] Sender public keys received. Decrypting...');
                            const decrypted = await decryptMessage(
                                mapped.content,
                                mapped.iv,
                                senderEncryptionPublicKey,
                                myKeys.encryption.privateKey
                            );
                            console.log('[Decryption] Success!');
                            mapped.content = decrypted;
                            // Mark as decrypted (clear encrypted flag since content is now plaintext)
                            mapped.encrypted = false;
                        } else {
                            console.error('[Decryption] Failed to retrieve public keys for sender:', mapped.from);
                            mapped.content = '[Encrypted message - sender key unavailable]';
                        }
                    }
                } catch (err) {
                    console.error('[Decryption] Failed to decrypt message:', err);
                    mapped.content = '[Encrypted message - decryption failed]';
                    void syncOwnKeysWithServer(user.username);
                }
            } else {
                console.log('[Decryption] Message is not encrypted or missing IV.');
            }

            // 1. Save locally
            await saveMessageLocally(user.username, mapped);
            await loadInbox();

            // 2. Send ACK to server
            socket.emit('message_delivered_ack', { msgId: mapped.id });

            setMessages((prev) => {
                // Deduplicate in UI state
                if (prev.find(m => m.id === mapped.id)) return prev;
                return [...prev, mapped];
            });
        };

        socket.on('direct_message', onDirectMessage);
        socket.on('message', onDirectMessage);

        return () => {
            socket.off('direct_message', onDirectMessage);
            socket.off('message', onDirectMessage);
        };
    }, [socket, user, requestUserPublicKeys, loadInbox]);

    const login = useCallback((username: string, password: string) => {
        return new Promise<void>((resolve, reject) => {
            if (!socket) return reject(new Error('No socket connection'));

            socket.emit('login', { username, password });

            const onSuccess = async (data: { token: string; username: string }) => {
                try {
                    localStorage.setItem('mesez_token', data.token);
                    localStorage.setItem('mesez_username', data.username);
                    socket.auth = { token: data.token };
                    setUser({ id: 'loggedin', username: data.username });

                    await syncOwnKeysWithServer(data.username);

                    resolve();
                } catch (err) {
                    reject(err instanceof Error ? err.message : 'Login process failed');
                } finally {
                    cleanup();
                }
            };

            const onError = (err: Error) => {
                reject(err.message || 'Login failed');
                cleanup();
            };

            const cleanup = () => {
                socket.off('login_success', onSuccess);
                socket.off('error', onError);
            };

            socket.on('login_success', onSuccess);
            socket.on('error', onError);
        });
    }, [socket, syncOwnKeysWithServer]);

    const register = useCallback((username: string, password: string) => {
        return new Promise<void>((resolve, reject) => {
            if (!socket) return reject(new Error('No socket connection'));
            const id = uuidv4();
            socket.emit('register', { id, username, password });

            const onSuccess = async () => {
                try {
                    // Generate and store keys for the new user
                    const publicKeys = await generateAndStoreKeys(username);

                    // Send public keys to server to store in database
                    socket.emit('upload_public_keys', {
                        userId: id,
                        username,
                        signingPublicKey: publicKeys.signingPublicKey,
                        encryptionPublicKey: publicKeys.encryptionPublicKey,
                        format: publicKeys.format,
                    });

                    resolve();
                } catch (err) {
                    console.error('Error generating and uploading keys:', err);
                    reject(err instanceof Error ? err.message : 'Failed to generate keys');
                } finally {
                    cleanup();
                }
            };

            const onError = (err: Error) => {
                reject(err.message || 'Registration failed');
                cleanup();
            };

            const cleanup = () => {
                socket.off('register_success', onSuccess);
                socket.off('error', onError);
            };

            socket.on('register_success', onSuccess);
            socket.on('error', onError);
        });
    }, [socket]);

    const logout = useCallback(() => {
        localStorage.removeItem('mesez_token');
        localStorage.removeItem('mesez_username');
        setUser(null);
        setMessages([]);
        setInbox([]);
        setOnlineUsers([]);
        setAllContacts([]);
        if (socket) {
            socket.auth = {};
            socket.disconnect();
            socket.connect();
        }
    }, [socket]);

    const sendMessage = useCallback(async (to: string, content: string) => {
        if (!socket || !user) return;

        let encryptedContent = content;
        let iv: string | undefined;
        let senderEncryptionPublicKey: string | undefined;

        try {
            // Load sender's private keys
            const myKeys = await loadStoredKeys(user.username);
            if (!myKeys) {
                console.error('My keys not found');
                // Try to regenerate keys if missing? For now just error.
                alert('Encryption error: Your keys are missing. Please re-login.');
                return;
            }

            // Fetch recipient's public keys
            const recipientKeys = await requestUserPublicKeys(to, 5000);

            if (!recipientKeys?.publicKeys) {
                console.error(`Public keys for user "${to}" not found.`);
                // If keys are missing, we cannot send E2EE. 
                // We should NOT send plain text.
                alert(`Cannot send message: Public keys for user "${to}" not found. The user may need to log in to generate keys.`);
                return;
            }

            if (myKeys && recipientKeys?.publicKeys) {
                const encryptionResult = await encryptMessage(
                    content,
                    recipientKeys.publicKeys.encryptionPublicKey,
                    myKeys.encryption.privateKey
                );
                encryptedContent = encryptionResult.encryptedContent;
                iv = encryptionResult.iv;
                senderEncryptionPublicKey = myKeys.encryption.publicKey;
            }
        } catch (err) {
            console.error('Encryption failed:', err);
            alert('Failed to encrypt message. Message was NOT sent.');
            return;
        }

        const msg: Message = {
            id: uuidv4(),
            from: user.username,
            to,
            content: encryptedContent,
            timestamp: new Date().toISOString(),
            status: 'sent',
            encrypted: true,
            iv: iv,
            sender_encryption_public_key: senderEncryptionPublicKey,
        };

        // Optimistic update with original content for display
        const displayMsg = { ...msg, content };
        setMessages((prev) => [...prev, displayMsg]);

        // Save our own message locally (decrypted version)
        if (user) {
            await saveMessageLocally(user.username, displayMsg);
            await loadInbox();
        }

        console.log('[Sender] Fragmenting message:', msg);

        try {
            const fragments = await fragmentMessage(msg as unknown as Record<string, unknown> & { to: string });
            fragments.forEach((fragment) => {
                socket.emit('fragment', fragment);
            });
        } catch (fragmentError) {
            console.error('Fragmentation failed, using legacy message event:', fragmentError);
            socket.emit('message', msg);
        }
    }, [socket, user, requestUserPublicKeys, loadInbox]);

    return (
        <SocketContext.Provider
            value={{
                socket,
                user,
                isConnected,
                login,
                register,
                logout,
                sendMessage,
                messages,
                setMessages,
                inbox,
                loadInbox,
                loadChatHistory,
                onlineUsers,
                allContacts,
            }}
        >
            {children}
        </SocketContext.Provider>
    );
};
