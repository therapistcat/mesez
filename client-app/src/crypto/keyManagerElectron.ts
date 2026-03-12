/**
 * Key manager for the Electron desktop app.
 *
 * Key generation and storage are delegated to the Electron main process via IPC,
 * which writes JSON files under client-app/.keys/<username>.json.
 * Messages are stored under client-app/.messages/<username>/<msgId>.json.
 */

export interface PublicKeys {
  signingPublicKey: string
  encryptionPublicKey: string
  format: string
}

interface StoredKeyPair {
  publicKey: string
  privateKey: string
}

export interface StoredKeys {
  username: string
  createdAt: string
  format: string
  signing: StoredKeyPair
  encryption: StoredKeyPair
}

export interface LocalInboxItem {
  contact: string
  last_message_preview: string
  last_timestamp: string
  unread_count: number
}

export function normalizeUsername(value: string): string {
  return (value || '').trim().toLowerCase()
}

/**
 * Generate cryptographic key pairs for signing (Ed25519) and encryption (X25519).
 * Keys are generated and stored by the Electron main process in .keys.
 */
export async function generateAndStoreKeys(username: string): Promise<PublicKeys> {
  const normalizedUsername = normalizeUsername(username)
  if (!normalizedUsername) {
    throw new Error('Username is required for key generation')
  }

  const result = await window.electronAPI.generateKeys(normalizedUsername)
  return result as PublicKeys
}

/**
 * Load stored keys from .keys/<username>.json via Electron IPC.
 */
export async function loadStoredKeys(username: string): Promise<StoredKeys | null> {
  const normalizedUsername = normalizeUsername(username)
  if (!normalizedUsername) {
    throw new Error('Username is required to load keys')
  }
  const result = await window.electronAPI.loadKeys(normalizedUsername)
  return (result as StoredKeys) ?? null
}

// ─── Message persistence ──────────────────────────────────────────────────────

/**
 * Save a message to .messages/<owner>/<msgId>.json via Electron IPC.
 */
export async function saveMessageLocally(owner: string, message: unknown): Promise<void> {
  const msg = message as Record<string, unknown>
  const msgId = typeof msg.id === 'string' ? msg.id.trim() : ''
  if (!msgId) return
  const ownerKey = normalizeUsername(owner)
  await window.electronAPI.saveMessage(ownerKey, message)
}

/**
 * Load chat history between owner and contact from .messages/<owner>/ via IPC.
 */
export async function loadLocalHistory(owner: string, contact: string): Promise<unknown[]> {
  const ownerKey = normalizeUsername(owner)
  const contactKey = normalizeUsername(contact)
  if (!ownerKey || !contactKey) return []
  return window.electronAPI.loadHistory(ownerKey, contactKey)
}

/**
 * Load inbox summary from .messages/<owner>/ via IPC.
 */
export async function loadLocalInbox(owner: string): Promise<LocalInboxItem[]> {
  const ownerKey = normalizeUsername(owner)
  if (!ownerKey) return []
  return window.electronAPI.loadInbox(ownerKey)
}
