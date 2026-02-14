/**
 * Message encryption utilities
 * Uses X25519 for key exchange and AES-GCM for message encryption
 */

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
 * Import a base64-encoded key into CryptoKey
 * Handles both "der-base64" and "spki-pkcs8-base64" formats
 */
async function importKey(
    base64Key: string,
    type: 'public' | 'private',
    algorithm: 'X25519' | 'Ed25519'
): Promise<CryptoKey> {
    const keyData = base64ToArrayBuffer(base64Key);
    const format = type === 'public' ? 'spki' : 'pkcs8';
    
    const keyUsages = algorithm === 'X25519' 
        ? (type === 'private' ? ['deriveKey', 'deriveBits'] : [])
        : (type === 'private' ? ['sign'] : ['verify']);

    return await window.crypto.subtle.importKey(
        format,
        keyData,
        { name: algorithm },
        false,
        keyUsages as KeyUsage[]
    );
}

/**
 * Derive shared AES-GCM key from X25519 key pair
 */
async function deriveSharedKey(
    privateKey: CryptoKey,
    publicKey: CryptoKey
): Promise<CryptoKey> {
    const sharedSecret = await window.crypto.subtle.deriveBits(
        {
            name: 'X25519',
            public: publicKey,
        },
        privateKey,
        256
    );

    // Derive AES-GCM key from shared secret
    return await window.crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt a message using recipient's public encryption key
 */
export async function encryptMessage(
    message: string,
    recipientPublicKey: string,
    senderPrivateKey: string
): Promise<{ encryptedContent: string; iv: string }> {
    // Import keys
    const recipientPubKey = await importKey(recipientPublicKey, 'public', 'X25519');
    const senderPrivKey = await importKey(senderPrivateKey, 'private', 'X25519');

    // Derive shared encryption key
    const sharedKey = await deriveSharedKey(senderPrivKey, recipientPubKey);

    // Generate random IV
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt message
    const encoder = new TextEncoder();
    const messageData = encoder.encode(message);

    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
        },
        sharedKey,
        messageData
    );

    return {
        encryptedContent: arrayBufferToBase64(encryptedData),
        iv: arrayBufferToBase64(iv.buffer),
    };
}

/**
 * Decrypt a message using sender's public encryption key
 */
export async function decryptMessage(
    encryptedContent: string,
    iv: string,
    senderPublicKey: string,
    recipientPrivateKey: string
): Promise<string> {
    // Import keys
    const senderPubKey = await importKey(senderPublicKey, 'public', 'X25519');
    const recipientPrivKey = await importKey(recipientPrivateKey, 'private', 'X25519');

    // Derive shared encryption key
    const sharedKey = await deriveSharedKey(recipientPrivKey, senderPubKey);

    // Decrypt message
    const encryptedData = base64ToArrayBuffer(encryptedContent);
    const ivData = base64ToArrayBuffer(iv);

    const decryptedData = await window.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: ivData,
        },
        sharedKey,
        encryptedData
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
}

/**
 * Sign a message using Ed25519 signing key
 */
export async function signMessage(
    message: string,
    signingPrivateKey: string
): Promise<string> {
    const privateKey = await importKey(signingPrivateKey, 'private', 'Ed25519');
    const encoder = new TextEncoder();
    const messageData = encoder.encode(message);

    const signature = await window.crypto.subtle.sign(
        { name: 'Ed25519' },
        privateKey,
        messageData
    );

    return arrayBufferToBase64(signature);
}

/**
 * Verify a message signature using Ed25519 public key
 */
export async function verifySignature(
    message: string,
    signature: string,
    signingPublicKey: string
): Promise<boolean> {
    try {
        const publicKey = await importKey(signingPublicKey, 'public', 'Ed25519');
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);
        const signatureData = base64ToArrayBuffer(signature);

        return await window.crypto.subtle.verify(
            { name: 'Ed25519' },
            publicKey,
            signatureData,
            messageData
        );
    } catch (err) {
        console.error('Signature verification failed:', err);
        return false;
    }
}
