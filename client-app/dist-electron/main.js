"use strict";
const electron = require("electron");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs/promises");
const url = require("url");
var _documentCurrentScript = typeof document !== "undefined" ? document.currentScript : null;
const __filename$1 = url.fileURLToPath(typeof document === "undefined" ? require("url").pathToFileURL(__filename).href : _documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === "SCRIPT" && _documentCurrentScript.src || new URL("main.js", document.baseURI).href);
const __dirname$1 = path.dirname(__filename$1);
const APP_STORAGE_DIR = process.cwd();
const KEYS_DIR = path.join(APP_STORAGE_DIR, ".keys");
const MESSAGES_DIR = path.join(APP_STORAGE_DIR, ".messages");
const PRELOAD_PATH = path.join(__dirname$1, "preload.js");
const RENDERER_DIST_PATH = path.join(APP_STORAGE_DIR, "dist", "index.html");
async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}
async function ensureStorageRoots() {
  await Promise.all([ensureDir(KEYS_DIR), ensureDir(MESSAGES_DIR)]);
}
function deriveAesKey(senderPrivateKeyBase64, recipientPublicKeyBase64) {
  const senderPrivateKey = crypto.createPrivateKey({
    key: Buffer.from(senderPrivateKeyBase64, "base64"),
    format: "der",
    type: "pkcs8"
  });
  const recipientPublicKey = crypto.createPublicKey({
    key: Buffer.from(recipientPublicKeyBase64, "base64"),
    format: "der",
    type: "spki"
  });
  const sharedSecret = crypto.diffieHellman({ privateKey: senderPrivateKey, publicKey: recipientPublicKey });
  return crypto.createHash("sha256").update(sharedSecret).digest();
}
function exportKeyPair(pair) {
  return {
    publicKey: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: pair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64")
  };
}
async function writeKeysFile(username, payload) {
  await ensureDir(KEYS_DIR);
  const filePath = path.join(KEYS_DIR, `${username}.json`);
  await fs.writeFile(filePath, JSON.stringify(payload, null, 2), {
    encoding: "utf8",
    mode: 384
  });
}
function createWindow() {
  const win = new electron.BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: "#0a0a0a",
    webPreferences: {
      preload: PRELOAD_PATH,
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  if (process.env["VITE_DEV_SERVER_URL"]) {
    win.loadURL(process.env["VITE_DEV_SERVER_URL"]);
  } else {
    win.loadFile(RENDERER_DIST_PATH);
  }
}
electron.ipcMain.handle("keys:store", async (_event, username, payload) => {
  await writeKeysFile(username, payload);
  return { success: true };
});
electron.ipcMain.handle("keys:generate", async (_event, username) => {
  const normalizedUsername = username.trim().toLowerCase();
  if (!normalizedUsername) {
    throw new Error("Username is required for key generation");
  }
  const payload = {
    username: normalizedUsername,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    format: "spki-pkcs8-base64",
    signing: exportKeyPair(crypto.generateKeyPairSync("ed25519")),
    encryption: exportKeyPair(crypto.generateKeyPairSync("x25519"))
  };
  await writeKeysFile(normalizedUsername, payload);
  return {
    signingPublicKey: payload.signing.publicKey,
    encryptionPublicKey: payload.encryption.publicKey,
    format: payload.format
  };
});
electron.ipcMain.handle("keys:load", async (_event, username) => {
  const filePath = path.join(KEYS_DIR, `${username}.json`);
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
});
electron.ipcMain.handle("crypto:encrypt-message", async (_event, payload) => {
  const aesKey = deriveAesKey(payload.senderPrivateKey, payload.recipientPublicKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(payload.message, "utf8")),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  const encryptedWithTag = Buffer.concat([ciphertext, authTag]);
  return {
    encryptedContent: encryptedWithTag.toString("base64"),
    iv: iv.toString("base64")
  };
});
electron.ipcMain.handle("crypto:decrypt-message", async (_event, payload) => {
  const aesKey = deriveAesKey(payload.recipientPrivateKey, payload.senderPublicKey);
  const iv = Buffer.from(payload.iv, "base64");
  const encryptedWithTag = Buffer.from(payload.encryptedContent, "base64");
  if (encryptedWithTag.length < 17) {
    throw new Error("Encrypted payload is too short");
  }
  const authTag = encryptedWithTag.subarray(encryptedWithTag.length - 16);
  const ciphertext = encryptedWithTag.subarray(0, encryptedWithTag.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString("utf8");
});
electron.ipcMain.handle("messages:save", async (_event, owner, message) => {
  const msgId = typeof message.id === "string" ? message.id.trim() : "";
  if (!msgId) return;
  const ownerDir = path.join(MESSAGES_DIR, owner);
  await ensureDir(ownerDir);
  const filePath = path.join(ownerDir, `${msgId}.json`);
  await fs.writeFile(filePath, JSON.stringify(message, null, 2), "utf8");
});
electron.ipcMain.handle("messages:load-history", async (_event, owner, contact) => {
  const ownerDir = path.join(MESSAGES_DIR, owner);
  const ownerKey = owner.trim().toLowerCase();
  const contactKey = contact.trim().toLowerCase();
  try {
    const files = await fs.readdir(ownerDir);
    const messages = [];
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      try {
        const raw = await fs.readFile(path.join(ownerDir, file), "utf8");
        const msg = JSON.parse(raw);
        const fromKey = String(msg.from ?? "").trim().toLowerCase();
        const toKey = String(msg.to ?? "").trim().toLowerCase();
        if (fromKey === ownerKey && toKey === contactKey || fromKey === contactKey && toKey === ownerKey) {
          messages.push(msg);
        }
      } catch {
      }
    }
    messages.sort(
      (a, b) => new Date(String(a.timestamp ?? 0)).getTime() - new Date(String(b.timestamp ?? 0)).getTime()
    );
    return messages;
  } catch (err) {
    if (err?.code === "ENOENT") return [];
    throw err;
  }
});
electron.ipcMain.handle("messages:load-inbox", async (_event, owner) => {
  const ownerDir = path.join(MESSAGES_DIR, owner);
  const ownerKey = owner.trim().toLowerCase();
  try {
    const files = await fs.readdir(ownerDir);
    const latestByPartner = /* @__PURE__ */ new Map();
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      try {
        const raw = await fs.readFile(path.join(ownerDir, file), "utf8");
        const msg = JSON.parse(raw);
        const fromKey = String(msg.from ?? "").trim().toLowerCase();
        const toKey = String(msg.to ?? "").trim().toLowerCase();
        const partnerKey = fromKey === ownerKey ? toKey : fromKey;
        if (!partnerKey || partnerKey === ownerKey) continue;
        const existing = latestByPartner.get(partnerKey);
        const rowTime = new Date(String(msg.timestamp ?? 0)).getTime();
        const existingTime = existing ? new Date(String(existing.timestamp ?? 0)).getTime() : -1;
        if (!existing || rowTime >= existingTime) {
          latestByPartner.set(partnerKey, msg);
        }
      } catch {
      }
    }
    const inbox = Array.from(latestByPartner.values()).map((msg) => {
      const fromKey = String(msg.from ?? "").toLowerCase();
      const contact = fromKey === ownerKey ? String(msg.to ?? "") : String(msg.from ?? "");
      return {
        contact,
        last_message_preview: String(msg.content ?? ""),
        last_timestamp: String(msg.timestamp ?? (/* @__PURE__ */ new Date(0)).toISOString()),
        unread_count: 0
      };
    }).sort(
      (a, b) => new Date(b.last_timestamp).getTime() - new Date(a.last_timestamp).getTime()
    );
    return inbox;
  } catch (err) {
    if (err?.code === "ENOENT") return [];
    throw err;
  }
});
electron.app.whenReady().then(createWindow);
electron.app.whenReady().then(ensureStorageRoots);
electron.app.on("window-all-closed", () => {
  if (process.platform !== "darwin") electron.app.quit();
});
electron.app.on("activate", () => {
  if (electron.BrowserWindow.getAllWindows().length === 0) createWindow();
});
