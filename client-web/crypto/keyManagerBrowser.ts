export interface PublicKeys {
    signingPublicKey: string;
    encryptionPublicKey: string;
    format: string;
}

interface StoredKeyPair {
    publicKey: string;
    privateKey: string;
}

interface StoredKeys {
    username: string;
    createdAt: string;
    format: string;
    signing: StoredKeyPair;
    encryption: StoredKeyPair;
}

const DB_NAME = 'mesez_keys';
const KEY_STORE_NAME = 'userKeys';
const MSG_STORE_NAME = 'messages';
const DB_VERSION = 2;

export function normalizeUsername(value: string): string {
    return (value || '').trim().toLowerCase();
}

export interface LocalInboxItem {
    contact: string;
    last_message_preview: string;
    last_timestamp: string;
    unread_count: number;
}

/**
 * Initialize IndexedDB for key storage
 */
function initDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);

        request.onupgradeneeded = (event: any) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
                db.createObjectStore(KEY_STORE_NAME, { keyPath: 'username' });
            }
            if (!db.objectStoreNames.contains(MSG_STORE_NAME)) {
                const msgStore = db.createObjectStore(MSG_STORE_NAME, { keyPath: 'id' });
                msgStore.createIndex('owner', 'owner', { unique: false });
                msgStore.createIndex('chatPartner', 'chatPartner', { unique: false });
                msgStore.createIndex('ownerKey', 'ownerKey', { unique: false });
                msgStore.createIndex('chatPartnerKey', 'chatPartnerKey', { unique: false });
            } else {
                const msgStore = event.target.transaction.objectStore(MSG_STORE_NAME);
                if (!msgStore.indexNames.contains('ownerKey')) {
                    msgStore.createIndex('ownerKey', 'ownerKey', { unique: false });
                }
                if (!msgStore.indexNames.contains('chatPartnerKey')) {
                    msgStore.createIndex('chatPartnerKey', 'chatPartnerKey', { unique: false });
                }
            }
        };
    });
}

/**
 * Converts a base64 string to an ArrayBuffer
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Converts an ArrayBuffer to a base64 string
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Generate cryptographic key pairs for signing and encryption
 * Uses EdDSA for signing and X25519 for encryption
 */
export async function generateKeyPair(): Promise<{
    signing: { publicKey: CryptoKey; privateKey: CryptoKey };
    encryption: { publicKey: CryptoKey; privateKey: CryptoKey };
}> {
    const signingPair = await window.crypto.subtle.generateKey(
        {
            name: 'Ed25519',
        },
        true, // extractable
        ['sign', 'verify']
    );

    const encryptionPair = await window.crypto.subtle.generateKey(
        {
            name: 'X25519',
        },
        true, // extractable
        ['deriveKey', 'deriveBits']
    );

    return {
        signing: signingPair as { publicKey: CryptoKey; privateKey: CryptoKey },
        encryption: encryptionPair as { publicKey: CryptoKey; privateKey: CryptoKey },
    };
}

/**
 * Export CryptoKey to base64 format
 */
async function exportKeyToBase64(key: CryptoKey, type: 'public' | 'private'): Promise<string> {
    const format = type === 'public' ? 'spki' : 'pkcs8';
    const exported = await window.crypto.subtle.exportKey(format, key);
    return arrayBufferToBase64(exported);
}

/**
 * Import a base64 key back to CryptoKey format
 */
async function importKeyFromBase64(base64: string, keyType: 'signing' | 'encryption', type: 'public' | 'private'): Promise<CryptoKey> {
    const buffer = base64ToArrayBuffer(base64);
    const format = type === 'public' ? 'spki' : 'pkcs8';
    const algorithm = keyType === 'signing' ? 'Ed25519' : 'X25519';
    const usages = keyType === 'signing' 
        ? (type === 'public' ? ['verify'] : ['sign'])
        : (type === 'public' ? ['deriveKey', 'deriveBits'] : ['deriveKey', 'deriveBits']);
    
    return await window.crypto.subtle.importKey(
        format,
        buffer,
        { name: algorithm },
        true, // extractable
        usages as KeyUsage[]
    );
}

/**
 * Generate key pair for user registration and store full pairs in IndexedDB
 * Returns only public keys to send to server
 */
export async function generateAndStoreKeys(username: string): Promise<PublicKeys> {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) {
        throw new Error('Username is required for key generation');
    }

    const { signing, encryption } = await generateKeyPair();

    const signingPublicKey = await exportKeyToBase64(signing.publicKey, 'public');
    const signingPrivateKey = await exportKeyToBase64(signing.privateKey, 'private');
    const encryptionPublicKey = await exportKeyToBase64(encryption.publicKey, 'public');
    const encryptionPrivateKey = await exportKeyToBase64(encryption.privateKey, 'private');

    const payload: StoredKeys = {
        username: normalizedUsername,
        createdAt: new Date().toISOString(),
        format: 'spki-pkcs8-base64',
        signing: {
            publicKey: signingPublicKey,
            privateKey: signingPrivateKey,
        },
        encryption: {
            publicKey: encryptionPublicKey,
            privateKey: encryptionPrivateKey,
        },
    };

    // Store full key pair in IndexedDB
    try {
        const db = await initDB();
        const transaction = db.transaction([KEY_STORE_NAME], 'readwrite');
        const store = transaction.objectStore(KEY_STORE_NAME);

        await new Promise<void>((resolve, reject) => {
            const request = store.put(payload);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    } catch (err) {
        console.warn('Could not store keys in IndexedDB:', err);
    }

    return {
        signingPublicKey,
        encryptionPublicKey,
        format: payload.format,
    };
}

/**
 * Load stored keys from IndexedDB
 */
export async function loadStoredKeys(username: string): Promise<StoredKeys | null> {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) {
        throw new Error('Username is required to load keys');
    }

    try {
        const db = await initDB();
        const transaction = db.transaction([KEY_STORE_NAME], 'readonly');
        const store = transaction.objectStore(KEY_STORE_NAME);

        return new Promise((resolve, reject) => {
            const request = store.get(normalizedUsername);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result || null);
        });
    } catch (err) {
        console.error('Error loading stored keys:', err);
        return null;
    }
}

/**
 * Load stored keys and convert base64 strings to usable CryptoKey objects
 */
export async function loadUsableKeys(username: string): Promise<{
    signing: { publicKey: CryptoKey; privateKey: CryptoKey };
    encryption: { publicKey: CryptoKey; privateKey: CryptoKey };
} | null> {
    const storedKeys = await loadStoredKeys(username);
    if (!storedKeys) {
        return null;
    }

    try {
        const signing = {
            publicKey: await importKeyFromBase64(storedKeys.signing.publicKey, 'signing', 'public'),
            privateKey: await importKeyFromBase64(storedKeys.signing.privateKey, 'signing', 'private'),
        };
        const encryption = {
            publicKey: await importKeyFromBase64(storedKeys.encryption.publicKey, 'encryption', 'public'),
            privateKey: await importKeyFromBase64(storedKeys.encryption.privateKey, 'encryption', 'private'),
        };
        return { signing, encryption };
    } catch (err) {
        console.error('Error converting stored keys to usable format:', err);
        return null;
    }
}

/**
 * Save a message locally in IndexedDB
 */
export async function saveMessageLocally(owner: string, message: any): Promise<void> {
    try {
        const db = await initDB();
        const transaction = db.transaction([MSG_STORE_NAME], 'readwrite');
        const store = transaction.objectStore(MSG_STORE_NAME);

        const ownerKey = normalizeUsername(owner);
        const sender = typeof message.from === 'string' ? message.from : '';
        const recipient = typeof message.to === 'string' ? message.to : '';

        // Normalize comparisons, preserve original display values.
        const isSentByOwner = normalizeUsername(sender) === ownerKey;
        const chatPartner = isSentByOwner ? recipient : sender;
        const chatPartnerKey = normalizeUsername(chatPartner);

        const entry = {
            ...message,
            owner,
            ownerKey,
            chatPartner,
            chatPartnerKey
        };

        await new Promise<void>((resolve, reject) => {
            const request = store.put(entry);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    } catch (err) {
        console.error('Error saving message locally:', err);
    }
}

/**
 * Load local chat history for a contact
 */
export async function loadLocalHistory(owner: string, contact: string): Promise<any[]> {
    try {
        const db = await initDB();
        const transaction = db.transaction([MSG_STORE_NAME], 'readonly');
        const store = transaction.objectStore(MSG_STORE_NAME);
        const ownerKey = normalizeUsername(owner);
        const contactKey = normalizeUsername(contact);

        return new Promise((resolve, reject) => {
            const results: any[] = [];
            const request = store.openCursor();

            request.onerror = () => reject(request.error);
            request.onsuccess = (event: any) => {
                const cursor = event.target.result;
                if (cursor) {
                    const row = cursor.value;
                    const rowOwnerKey = normalizeUsername(cursor.value.ownerKey || cursor.value.owner || '');
                    const rowPartnerKey = normalizeUsername(cursor.value.chatPartnerKey || cursor.value.chatPartner || '');
                    if (rowOwnerKey === ownerKey && rowPartnerKey === contactKey) {
                        results.push(row);
                    }
                    cursor.continue();
                } else {
                    // Sort by timestamp
                    results.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
                    resolve(results);
                }
            };
        });
    } catch (err) {
        console.error('Error loading local history:', err);
        return [];
    }
}

export async function loadLocalInbox(owner: string): Promise<LocalInboxItem[]> {
    try {
        const db = await initDB();
        const transaction = db.transaction([MSG_STORE_NAME], 'readonly');
        const store = transaction.objectStore(MSG_STORE_NAME);
        const ownerKey = normalizeUsername(owner);
        const request = store.openCursor();

        return await new Promise((resolve, reject) => {
            const latestByPartner = new Map<string, any>();

            request.onerror = () => reject(request.error);
            request.onsuccess = (event: any) => {
                const cursor = event.target.result;
                if (cursor) {
                    const row = cursor.value;
                    const rowOwnerKey = normalizeUsername(row.ownerKey || row.owner || '');
                    if (rowOwnerKey === ownerKey) {
                        const partner = String(row.chatPartner || '').trim();
                        if (partner) {
                            const key = normalizeUsername(partner);
                            const existing = latestByPartner.get(key);
                            const rowTime = new Date(row.timestamp || 0).getTime();
                            const existingTime = existing ? new Date(existing.timestamp || 0).getTime() : -1;
                            if (!existing || rowTime >= existingTime) {
                                latestByPartner.set(key, row);
                            }
                        }
                    }
                    cursor.continue();
                    return;
                }

                const inbox: LocalInboxItem[] = Array.from(latestByPartner.values())
                    .map((row) => ({
                        contact: String(row.chatPartner || ''),
                        last_message_preview: String(row.content || ''),
                        last_timestamp: String(row.timestamp || new Date(0).toISOString()),
                        unread_count: 0
                    }))
                    .sort((a, b) => new Date(b.last_timestamp).getTime() - new Date(a.last_timestamp).getTime());

                resolve(inbox);
            };
        });
    } catch (err) {
        console.error('Error loading local inbox:', err);
        return [];
    }
}
