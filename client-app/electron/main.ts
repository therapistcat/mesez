import { app, BrowserWindow, ipcMain } from 'electron'
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  KeyObject,
  randomBytes,
} from 'crypto'
import path from 'path'
import fs from 'fs/promises'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Persist data in the project workspace during development as requested.
const APP_STORAGE_DIR = process.cwd()
const KEYS_DIR = path.join(APP_STORAGE_DIR, '.keys')
const MESSAGES_DIR = path.join(APP_STORAGE_DIR, '.messages')
const PRELOAD_PATH = path.join(__dirname, 'preload.js')
const RENDERER_DIST_PATH = path.join(APP_STORAGE_DIR, 'dist', 'index.html')

async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true })
}

async function ensureStorageRoots(): Promise<void> {
  await Promise.all([ensureDir(KEYS_DIR), ensureDir(MESSAGES_DIR)])
}

type StoredKeyPair = {
  publicKey: string
  privateKey: string
}

type StoredKeys = {
  username: string
  createdAt: string
  format: string
  signing: StoredKeyPair
  encryption: StoredKeyPair
}

type EncryptPayload = {
  message: string
  recipientPublicKey: string
  senderPrivateKey: string
}

type DecryptPayload = {
  encryptedContent: string
  iv: string
  senderPublicKey: string
  recipientPrivateKey: string
}

function deriveAesKey(senderPrivateKeyBase64: string, recipientPublicKeyBase64: string): Buffer {
  const senderPrivateKey = createPrivateKey({
    key: Buffer.from(senderPrivateKeyBase64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  })
  const recipientPublicKey = createPublicKey({
    key: Buffer.from(recipientPublicKeyBase64, 'base64'),
    format: 'der',
    type: 'spki',
  })

  // Derive a stable 32-byte AES key from X25519 shared secret.
  const sharedSecret = diffieHellman({ privateKey: senderPrivateKey, publicKey: recipientPublicKey })
  return createHash('sha256').update(sharedSecret).digest()
}

function exportKeyPair(pair: { publicKey: KeyObject; privateKey: KeyObject }): StoredKeyPair {
  return {
    publicKey: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  }
}

async function writeKeysFile(username: string, payload: StoredKeys): Promise<void> {
  await ensureDir(KEYS_DIR)
  const filePath = path.join(KEYS_DIR, `${username}.json`)
  await fs.writeFile(filePath, JSON.stringify(payload, null, 2), {
    encoding: 'utf8',
    mode: 0o600,
  })
}

function createWindow(): void {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0a0a0a',
    webPreferences: {
      preload: PRELOAD_PATH,
      contextIsolation: true,
      nodeIntegration: false,
    },
  })

  if (process.env['VITE_DEV_SERVER_URL']) {
    win.loadURL(process.env['VITE_DEV_SERVER_URL'])
  } else {
    win.loadFile(RENDERER_DIST_PATH)
  }
}

// ─── Key Storage IPC Handlers ─────────────────────────────────────────────────

ipcMain.handle('keys:store', async (_event, username: string, payload: StoredKeys) => {
  await writeKeysFile(username, payload)
  return { success: true }
})

ipcMain.handle('keys:generate', async (_event, username: string) => {
  const normalizedUsername = username.trim().toLowerCase()
  if (!normalizedUsername) {
    throw new Error('Username is required for key generation')
  }

  const payload: StoredKeys = {
    username: normalizedUsername,
    createdAt: new Date().toISOString(),
    format: 'spki-pkcs8-base64',
    signing: exportKeyPair(generateKeyPairSync('ed25519')),
    encryption: exportKeyPair(generateKeyPairSync('x25519')),
  }

  await writeKeysFile(normalizedUsername, payload)

  return {
    signingPublicKey: payload.signing.publicKey,
    encryptionPublicKey: payload.encryption.publicKey,
    format: payload.format,
  }
})

ipcMain.handle('keys:load', async (_event, username: string) => {
  const filePath = path.join(KEYS_DIR, `${username}.json`)
  try {
    const raw = await fs.readFile(filePath, 'utf8')
    return JSON.parse(raw)
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return null
    throw err
  }
})

ipcMain.handle('crypto:encrypt-message', async (_event, payload: EncryptPayload) => {
  const aesKey = deriveAesKey(payload.senderPrivateKey, payload.recipientPublicKey)
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv)

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(payload.message, 'utf8')),
    cipher.final(),
  ])
  const authTag = cipher.getAuthTag()

  // WebCrypto AES-GCM returns ciphertext with auth tag appended; keep wire format compatible.
  const encryptedWithTag = Buffer.concat([ciphertext, authTag])

  return {
    encryptedContent: encryptedWithTag.toString('base64'),
    iv: iv.toString('base64'),
  }
})

ipcMain.handle('crypto:decrypt-message', async (_event, payload: DecryptPayload) => {
  const aesKey = deriveAesKey(payload.recipientPrivateKey, payload.senderPublicKey)
  const iv = Buffer.from(payload.iv, 'base64')
  const encryptedWithTag = Buffer.from(payload.encryptedContent, 'base64')

  if (encryptedWithTag.length < 17) {
    throw new Error('Encrypted payload is too short')
  }

  const authTag = encryptedWithTag.subarray(encryptedWithTag.length - 16)
  const ciphertext = encryptedWithTag.subarray(0, encryptedWithTag.length - 16)

  const decipher = createDecipheriv('aes-256-gcm', aesKey, iv)
  decipher.setAuthTag(authTag)
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  return decrypted.toString('utf8')
})

// ─── Message Storage IPC Handlers ─────────────────────────────────────────────

ipcMain.handle('messages:save', async (_event, owner: string, message: Record<string, unknown>) => {
  const msgId = typeof message.id === 'string' ? message.id.trim() : ''
  if (!msgId) return
  const ownerDir = path.join(MESSAGES_DIR, owner)
  await ensureDir(ownerDir)
  const filePath = path.join(ownerDir, `${msgId}.json`)
  await fs.writeFile(filePath, JSON.stringify(message, null, 2), 'utf8')
})

ipcMain.handle('messages:load-history', async (_event, owner: string, contact: string) => {
  const ownerDir = path.join(MESSAGES_DIR, owner)
  const ownerKey = owner.trim().toLowerCase()
  const contactKey = contact.trim().toLowerCase()

  try {
    const files = await fs.readdir(ownerDir)
    const messages: Record<string, unknown>[] = []

    for (const file of files) {
      if (!file.endsWith('.json')) continue
      try {
        const raw = await fs.readFile(path.join(ownerDir, file), 'utf8')
        const msg = JSON.parse(raw) as Record<string, unknown>
        const fromKey = String(msg.from ?? '').trim().toLowerCase()
        const toKey = String(msg.to ?? '').trim().toLowerCase()
        if (
          (fromKey === ownerKey && toKey === contactKey) ||
          (fromKey === contactKey && toKey === ownerKey)
        ) {
          messages.push(msg)
        }
      } catch {
        // skip malformed files
      }
    }

    messages.sort(
      (a, b) =>
        new Date(String(a.timestamp ?? 0)).getTime() -
        new Date(String(b.timestamp ?? 0)).getTime()
    )
    return messages
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return []
    throw err
  }
})

ipcMain.handle('messages:load-inbox', async (_event, owner: string) => {
  const ownerDir = path.join(MESSAGES_DIR, owner)
  const ownerKey = owner.trim().toLowerCase()

  try {
    const files = await fs.readdir(ownerDir)
    const latestByPartner = new Map<string, Record<string, unknown>>()

    for (const file of files) {
      if (!file.endsWith('.json')) continue
      try {
        const raw = await fs.readFile(path.join(ownerDir, file), 'utf8')
        const msg = JSON.parse(raw) as Record<string, unknown>
        const fromKey = String(msg.from ?? '').trim().toLowerCase()
        const toKey = String(msg.to ?? '').trim().toLowerCase()
        const partnerKey = fromKey === ownerKey ? toKey : fromKey
        if (!partnerKey || partnerKey === ownerKey) continue

        const existing = latestByPartner.get(partnerKey)
        const rowTime = new Date(String(msg.timestamp ?? 0)).getTime()
        const existingTime = existing
          ? new Date(String(existing.timestamp ?? 0)).getTime()
          : -1

        if (!existing || rowTime >= existingTime) {
          latestByPartner.set(partnerKey, msg)
        }
      } catch {
        // skip malformed files
      }
    }

    const inbox = Array.from(latestByPartner.values())
      .map((msg) => {
        const fromKey = String(msg.from ?? '').toLowerCase()
        const contact = fromKey === ownerKey ? String(msg.to ?? '') : String(msg.from ?? '')
        return {
          contact,
          last_message_preview: String(msg.content ?? ''),
          last_timestamp: String(msg.timestamp ?? new Date(0).toISOString()),
          unread_count: 0,
        }
      })
      .sort(
        (a, b) =>
          new Date(b.last_timestamp).getTime() - new Date(a.last_timestamp).getTime()
      )

    return inbox
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return []
    throw err
  }
})

// ─── App Lifecycle ─────────────────────────────────────────────────────────────

app.whenReady().then(createWindow)
app.whenReady().then(ensureStorageRoots)

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})
