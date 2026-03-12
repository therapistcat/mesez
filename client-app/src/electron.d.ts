export interface ElectronLocalInboxItem {
  contact: string
  last_message_preview: string
  last_timestamp: string
  unread_count: number
}

declare global {
  interface Window {
    electronAPI: {
      storeKeys: (username: string, payload: object) => Promise<{ success: boolean }>
      generateKeys: (username: string) => Promise<unknown>
      loadKeys: (username: string) => Promise<unknown>
      saveMessage: (owner: string, message: unknown) => Promise<void>
      loadHistory: (owner: string, contact: string) => Promise<unknown[]>
      loadInbox: (owner: string) => Promise<ElectronLocalInboxItem[]>
      encryptMessage: (
        message: string,
        recipientPublicKey: string,
        senderPrivateKey: string
      ) => Promise<{ encryptedContent: string; iv: string }>
      decryptMessage: (
        encryptedContent: string,
        iv: string,
        senderPublicKey: string,
        recipientPrivateKey: string
      ) => Promise<string>
    }
  }
}
