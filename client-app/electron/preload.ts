import { contextBridge, ipcRenderer } from 'electron'

export interface LocalInboxItem {
  contact: string
  last_message_preview: string
  last_timestamp: string
  unread_count: number
}

contextBridge.exposeInMainWorld('electronAPI', {
  storeKeys: (username: string, payload: object): Promise<{ success: boolean }> =>
    ipcRenderer.invoke('keys:store', username, payload),

  generateKeys: (username: string): Promise<unknown> =>
    ipcRenderer.invoke('keys:generate', username),

  loadKeys: (username: string): Promise<unknown> =>
    ipcRenderer.invoke('keys:load', username),

  saveMessage: (owner: string, message: unknown): Promise<void> =>
    ipcRenderer.invoke('messages:save', owner, message),

  loadHistory: (owner: string, contact: string): Promise<unknown[]> =>
    ipcRenderer.invoke('messages:load-history', owner, contact),

  loadInbox: (owner: string): Promise<LocalInboxItem[]> =>
    ipcRenderer.invoke('messages:load-inbox', owner),

  encryptMessage: (
    message: string,
    recipientPublicKey: string,
    senderPrivateKey: string
  ): Promise<{ encryptedContent: string; iv: string }> =>
    ipcRenderer.invoke('crypto:encrypt-message', {
      message,
      recipientPublicKey,
      senderPrivateKey,
    }),

  decryptMessage: (
    encryptedContent: string,
    iv: string,
    senderPublicKey: string,
    recipientPrivateKey: string
  ): Promise<string> =>
    ipcRenderer.invoke('crypto:decrypt-message', {
      encryptedContent,
      iv,
      senderPublicKey,
      recipientPrivateKey,
    }),
})
