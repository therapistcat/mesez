"use strict";
const electron = require("electron");
electron.contextBridge.exposeInMainWorld("electronAPI", {
  storeKeys: (username, payload) => electron.ipcRenderer.invoke("keys:store", username, payload),
  generateKeys: (username) => electron.ipcRenderer.invoke("keys:generate", username),
  loadKeys: (username) => electron.ipcRenderer.invoke("keys:load", username),
  saveMessage: (owner, message) => electron.ipcRenderer.invoke("messages:save", owner, message),
  loadHistory: (owner, contact) => electron.ipcRenderer.invoke("messages:load-history", owner, contact),
  loadInbox: (owner) => electron.ipcRenderer.invoke("messages:load-inbox", owner),
  encryptMessage: (message, recipientPublicKey, senderPrivateKey) => electron.ipcRenderer.invoke("crypto:encrypt-message", {
    message,
    recipientPublicKey,
    senderPrivateKey
  }),
  decryptMessage: (encryptedContent, iv, senderPublicKey, recipientPrivateKey) => electron.ipcRenderer.invoke("crypto:decrypt-message", {
    encryptedContent,
    iv,
    senderPublicKey,
    recipientPrivateKey
  })
});
