/**
 * Message encryption utilities
 * Uses X25519 for key exchange and AES-GCM for message encryption.
 * This file is identical to client-web/crypto/messageEncryption.ts.
 */

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

async function importKey(
  base64Key: string,
  type: 'public' | 'private',
  algorithm: 'X25519' | 'Ed25519'
): Promise<CryptoKey> {
  const keyData = base64ToArrayBuffer(base64Key)
  const format = type === 'public' ? 'spki' : 'pkcs8'
  const keyUsages =
    algorithm === 'X25519'
      ? type === 'private'
        ? ['deriveKey', 'deriveBits']
        : []
      : type === 'private'
        ? ['sign']
        : ['verify']

  return window.crypto.subtle.importKey(
    format,
    keyData,
    { name: algorithm },
    false,
    keyUsages as KeyUsage[]
  )
}

export async function encryptMessage(
  message: string,
  recipientPublicKey: string,
  senderPrivateKey: string
): Promise<{ encryptedContent: string; iv: string }> {
  return window.electronAPI.encryptMessage(message, recipientPublicKey, senderPrivateKey)
}

export async function decryptMessage(
  encryptedContent: string,
  iv: string,
  senderPublicKey: string,
  recipientPrivateKey: string
): Promise<string> {
  return window.electronAPI.decryptMessage(
    encryptedContent,
    iv,
    senderPublicKey,
    recipientPrivateKey
  )
}

export async function signMessage(message: string, signingPrivateKey: string): Promise<string> {
  const privateKey = await importKey(signingPrivateKey, 'private', 'Ed25519')
  const encoder = new TextEncoder()
  const signature = await window.crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    encoder.encode(message)
  )
  return arrayBufferToBase64(signature)
}

export async function verifySignature(
  message: string,
  signature: string,
  signingPublicKey: string
): Promise<boolean> {
  try {
    const publicKey = await importKey(signingPublicKey, 'public', 'Ed25519')
    const encoder = new TextEncoder()
    return window.crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      base64ToArrayBuffer(signature),
      encoder.encode(message)
    )
  } catch {
    return false
  }
}
