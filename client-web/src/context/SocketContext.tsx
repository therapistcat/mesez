import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import type { ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';
import { v4 as uuidv4 } from 'uuid';
import { generateAndStoreKeys, loadStoredKeys } from '../../crypto/keyManagerBrowser';
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

const SERVER_URL = 'http://localhost:3000';

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

    const loadInbox = useCallback(() => {
        if (socket) socket.emit('get_inbox');
    }, [socket]);

    const loadChatHistory = useCallback((contact: string) => {
        if (socket) socket.emit('get_chat_history', { contact });
    }, [socket]);

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

        const onDirectMessage = async (msg: any) => {
            const mapped = mapServerMessage(msg);
            
            // Decrypt message if encrypted
            if (mapped.encrypted && mapped.iv && user) {
                try {
                    const myKeys = await loadStoredKeys(user.username);
                    if (myKeys) {
                        // Fetch sender's public key
                        newSocket.emit('get_user_public_keys', { username: mapped.from });
                        
                        const senderKeys = await new Promise<any>((resolve) => {
                            const onKeys = (data: any) => {
                                newSocket.off('user_public_keys_response', onKeys);
                                resolve(data);
                            };
                            newSocket.on('user_public_keys_response', onKeys);
                            setTimeout(() => resolve(null), 3000);
                        });

                        if (senderKeys?.publicKeys) {
                            const decrypted = await decryptMessage(
                                mapped.content,
                                mapped.iv,
                                senderKeys.publicKeys.encryptionPublicKey,
                                myKeys.encryption.privateKey
                            );
                            mapped.content = decrypted;
                        }
                    }
                } catch (err) {
                    console.error('Failed to decrypt message:', err);
                    mapped.content = '[Encrypted message - decryption failed]';
                }
            }
            
            setMessages((prev) => [...prev, mapped]);
        };

        newSocket.on('direct_message', onDirectMessage);
        // Backward compatibility with legacy server event.
        newSocket.on('message', onDirectMessage);

        newSocket.on('chat_history', async (data: { contact: string; messages: any[] }) => {
            // Map server field names to client field names
            const mapped = data.messages.map(mapServerMessage);
            
            // Decrypt messages if needed
            if (user) {
                const myKeys = await loadStoredKeys(user.username);
                const contactKeys = await new Promise<any>((resolve) => {
                    newSocket.emit('get_user_public_keys', { username: data.contact });
                    const onKeys = (keyData: any) => {
                        newSocket.off('user_public_keys_response', onKeys);
                        resolve(keyData);
                    };
                    newSocket.on('user_public_keys_response', onKeys);
                    setTimeout(() => resolve(null), 3000);
                });

                if (myKeys && contactKeys?.publicKeys) {
                    for (const msg of mapped) {
                        if (msg.encrypted && msg.iv) {
                            try {
                                // Decrypt based on whether I sent or received
                                const senderKey = msg.from === user.username 
                                    ? contactKeys.publicKeys.encryptionPublicKey
                                    : contactKeys.publicKeys.encryptionPublicKey;
                                
                                const decrypted = await decryptMessage(
                                    msg.content,
                                    msg.iv,
                                    senderKey,
                                    myKeys.encryption.privateKey
                                );
                                msg.content = decrypted;
                            } catch (err) {
                                console.error('Failed to decrypt chat history message:', err);
                                msg.content = '[Encrypted message]';
                            }
                        }
                    }
                }
            }
            
            setMessages(mapped);
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
        } else {
            newSocket.connect();
        }

        return () => {
            newSocket.off('connect');
            newSocket.off('disconnect');
            newSocket.off('connect_error');
            newSocket.off('error');
            newSocket.off('direct_message');
            newSocket.off('message');
            newSocket.off('chat_history');
            newSocket.off('inbox_data');
            newSocket.off('online_users_data');
            newSocket.off('all_contacts_data');
            newSocket.off('user_status');
            newSocket.close();
        };
    }, []);

    const login = useCallback((username: string, password: string) => {
        return new Promise<void>(async (resolve, reject) => {
            if (!socket) return reject('No socket connection');

            socket.emit('login', { username, password });

            const onSuccess = async (data: { token: string; username: string }) => {
                try {
                    localStorage.setItem('mesez_token', data.token);
                    localStorage.setItem('mesez_username', data.username);
                    socket.auth = { token: data.token };
                    setUser({ id: 'loggedin', username: data.username });

                    // Check if user has keys on the server
                    const hasKeys = await new Promise<boolean>((resolveKeys) => {
                        socket.emit('check_public_keys', { username: data.username });

                        const onKeysCheck = (response: { exists: boolean }) => {
                            socket.off('public_keys_check_response', onKeysCheck);
                            resolveKeys(response.exists);
                        };

                        // Timeout if no response
                        const timeout = setTimeout(() => {
                            socket.off('public_keys_check_response', onKeysCheck);
                            resolveKeys(false); // Assume no keys if no response
                        }, 3000);

                        socket.on('public_keys_check_response', (response) => {
                            clearTimeout(timeout);
                            onKeysCheck(response);
                        });
                    });

                    // If no keys exist, generate and upload new ones
                    if (!hasKeys) {
                        try {
                            const publicKeys = await generateAndStoreKeys(data.username);
                            socket.emit('upload_public_keys', {
                                username: data.username,
                                signingPublicKey: publicKeys.signingPublicKey,
                                encryptionPublicKey: publicKeys.encryptionPublicKey,
                                format: publicKeys.format,
                            });
                        } catch (err) {
                            console.error('Error generating keys on login:', err);
                            // Don't reject login if key generation fails, just log it
                        }
                    }

                    resolve();
                } catch (err) {
                    reject(err instanceof Error ? err.message : 'Login process failed');
                } finally {
                    cleanup();
                }
            };

            const onError = (err: any) => {
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
    }, [socket]);

    const register = useCallback((username: string, password: string) => {
        return new Promise<void>(async (resolve, reject) => {
            if (!socket) return reject('No socket connection');
            const id=uuidv4();
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

            const onError = (err: any) => {
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
        let encrypted = false;

        try {
            // Load sender's private keys
            const myKeys = await loadStoredKeys(user.username);
            
            // Fetch recipient's public keys
            const recipientKeys = await new Promise<any>((resolve) => {
                socket.emit('get_user_public_keys', { username: to });
                
                const onKeys = (data: any) => {
                    socket.off('user_public_keys_response', onKeys);
                    resolve(data);
                };
                
                socket.on('user_public_keys_response', onKeys);
                setTimeout(() => resolve(null), 3000);
            });

            if (myKeys && recipientKeys?.publicKeys) {
                const encryptionResult = await encryptMessage(
                    content,
                    recipientKeys.publicKeys.encryptionPublicKey,
                    myKeys.encryption.privateKey
                );
                encryptedContent = encryptionResult.encryptedContent;
                iv = encryptionResult.iv;
                encrypted = true;
            }
        } catch (err) {
            console.error('Encryption failed, sending unencrypted:', err);
        }

        const msg: Message = {
            id: uuidv4(),
            from: user.username,
            to,
            content: encrypted ? encryptedContent : content,
            timestamp: new Date().toISOString(),
            status: 'sent',
            encrypted,
        };
        if (iv) {
            msg.iv = iv;
        }

        // Optimistic update with original content for display
        setMessages((prev) => [...prev, { ...msg, content }]);
        try {
            const fragments = await fragmentMessage(msg as Record<string, unknown> & { to: string });
            fragments.forEach((fragment) => {
                socket.emit('fragment', fragment);
            });
        } catch (fragmentError) {
            console.error('Fragmentation failed, using legacy message event:', fragmentError);
            socket.emit('message', msg);
        }
    }, [socket, user]);

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
