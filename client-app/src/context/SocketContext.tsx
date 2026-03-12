import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import type { ReactNode } from 'react'
import { io, Socket } from 'socket.io-client'
import { v4 as uuidv4 } from 'uuid'
import {
  generateAndStoreKeys,
  loadStoredKeys,
  saveMessageLocally,
  loadLocalHistory,
  loadLocalInbox,
  normalizeUsername,
} from '../crypto/keyManagerElectron'
import { encryptMessage, decryptMessage } from '../crypto/messageEncryption'
import { fragmentMessage } from '../utils/FragmentChopper'

interface User {
  id: string
  username: string
}

export interface Message {
  id: string
  from: string
  to: string
  content: string
  timestamp: string
  status?: string
  encrypted?: boolean
  iv?: string
  sender_encryption_public_key?: string
}

export interface InboxItem {
  contact: string
  last_message_preview: string
  last_timestamp: string
  unread_count: number
}

export interface KeyStatus {
  state: 'checking' | 'ready' | 'syncing' | 'local-only' | 'missing' | 'error'
  detail: string
}

interface SocketContextType {
  socket: Socket | null
  user: User | null
  isConnected: boolean
  keyStatus: KeyStatus
  login: (username: string, password: string) => Promise<void>
  register: (username: string, password: string) => Promise<void>
  logout: () => void
  sendMessage: (to: string, content: string) => void
  messages: Message[]
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>
  inbox: InboxItem[]
  loadInbox: () => void
  loadChatHistory: (contact: string) => void
  onlineUsers: string[]
  allContacts: string[]
}

const SocketContext = createContext<SocketContextType | undefined>(undefined)

export const useSocket = () => {
  const context = useContext(SocketContext)
  if (!context) throw new Error('useSocket must be used within a SocketProvider')
  return context
}

const SERVER_URL = (import.meta.env.VITE_SERVER_URL as string) || 'http://localhost:3000'

function looksLikeCiphertext(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const trimmed = value.trim()
  if (trimmed.length < 24) return false
  if (trimmed.length % 4 !== 0) return false
  return /^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)
}

function mapServerMessage(msg: Record<string, unknown>): Message {
  return {
    id: typeof msg.id === 'string' ? msg.id : '',
    from: typeof msg.from === 'string' ? msg.from : '',
    to: typeof msg.to === 'string' ? msg.to : '',
    content: typeof msg.content === 'string' ? msg.content : String(msg.content ?? ''),
    timestamp: String(msg.timestamp ?? ''),
    status: typeof msg.status === 'string' ? msg.status : undefined,
    encrypted: typeof msg.encrypted === 'boolean' ? msg.encrypted : undefined,
    iv: typeof msg.iv === 'string' ? msg.iv : undefined,
    sender_encryption_public_key:
      typeof msg.sender_encryption_public_key === 'string'
        ? msg.sender_encryption_public_key
        : undefined,
  }
}

export const SocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [user, setUser] = useState<User | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [keyStatus, setKeyStatus] = useState<KeyStatus>({
    state: 'checking',
    detail: 'Checking local keys',
  })
  const [messages, setMessages] = useState<Message[]>([])
  const [inbox, setInbox] = useState<InboxItem[]>([])
  const [onlineUsers, setOnlineUsers] = useState<string[]>([])
  const [allContacts, setAllContacts] = useState<string[]>([])

  const uploadPublicKeys = useCallback(
    (
      username: string,
      keys: { signing: { publicKey: string }; encryption: { publicKey: string }; format: string }
    ) => {
      if (!socket) return
      socket.emit('upload_public_keys', {
        username,
        signingPublicKey: keys.signing.publicKey,
        encryptionPublicKey: keys.encryption.publicKey,
        format: keys.format,
      })
    },
    [socket]
  )

  const setCheckingKeyStatus = useCallback((detail: string) => {
    setKeyStatus({ state: 'checking', detail })
  }, [])

  const loadInbox = useCallback(async () => {
    if (!user) { setInbox([]); return }
    const localInbox = await loadLocalInbox(user.username)
    setInbox(localInbox)
  }, [user])

  const loadChatHistory = useCallback(
    async (contact: string) => {
      if (!user) return
      const history = (await loadLocalHistory(user.username, contact)) as Message[]
      const currentUserKey = normalizeUsername(user.username)
      const myKeys = await ensureOwnKeysReady(user.username)

      const decryptedHistory = await Promise.all(
        history.map(async (msg) => {
          if (
            typeof msg.content === 'string' &&
            looksLikeCiphertext(msg.content) &&
            (!msg.encrypted || !msg.iv)
          ) {
            return { ...msg, content: '[Encrypted message - metadata missing]' }
          }

          if (msg.encrypted && msg.iv && msg.content && typeof msg.content === 'string') {
            if (msg.content.startsWith('[Encrypted message')) return msg
            if (!looksLikeCiphertext(msg.content)) {
              return { ...msg, encrypted: false, iv: undefined, sender_encryption_public_key: undefined }
            }

            try {
              if (myKeys) {
                const senderKey = normalizeUsername(msg.from || '')
                const recipientKey = normalizeUsername(msg.to || '')
                const isSentByCurrentUser = senderKey === currentUserKey
                const keyLookupUsername = isSentByCurrentUser ? recipientKey : senderKey
                let peerEncryptionPublicKey = isSentByCurrentUser
                  ? ''
                  : msg.sender_encryption_public_key

                if (!peerEncryptionPublicKey && socket && keyLookupUsername) {
                  const senderKeys = await new Promise<Record<string, unknown> | null>((resolve) => {
                    let settled = false
                    const timer = setTimeout(() => {
                      if (settled) return
                      socket.off('user_public_keys_response', onKeys)
                      resolve(null)
                    }, 3000)

                    const onKeys = (data: Record<string, unknown>) => {
                      const responseUsername = normalizeUsername(String(data?.username ?? ''))
                      if (responseUsername !== keyLookupUsername) return
                      settled = true
                      clearTimeout(timer)
                      socket.off('user_public_keys_response', onKeys)
                      resolve(data)
                    }

                    socket.on('user_public_keys_response', onKeys)
                    socket.emit('get_user_public_keys', { username: keyLookupUsername })
                  })
                  const pk = (senderKeys as Record<string, Record<string, string>> | null)
                    ?.publicKeys?.encryptionPublicKey
                  peerEncryptionPublicKey = pk
                }

                if (peerEncryptionPublicKey) {
                  const decrypted = await decryptMessage(
                    msg.content,
                    msg.iv,
                    peerEncryptionPublicKey,
                    myKeys.encryption.privateKey
                  )
                  const decryptedMessage = {
                    ...msg,
                    content: decrypted,
                    encrypted: false,
                    iv: undefined,
                    sender_encryption_public_key: undefined,
                  }
                  await saveMessageLocally(user.username, decryptedMessage)
                  return decryptedMessage
                }

                const unresolvedMessage = {
                  ...msg,
                  content: '[Encrypted message - key unavailable]',
                  encrypted: false,
                  iv: undefined,
                  sender_encryption_public_key: undefined,
                }
                await saveMessageLocally(user.username, unresolvedMessage)
                return unresolvedMessage
              }
            } catch {
              const failedMessage = {
                ...msg,
                content: '[Encrypted message - decryption failed]',
                encrypted: false,
                iv: undefined,
                sender_encryption_public_key: undefined,
              }
              await saveMessageLocally(user.username, failedMessage)
              return failedMessage
            }
          }
          return msg
        })
      )

      setMessages(decryptedHistory)
    },
    [user, socket]
  )

  const requestUserPublicKeys = useCallback(
    (username: string, timeoutMs = 5000) => {
      return new Promise<Record<string, unknown> | null>((resolve) => {
        if (!socket) { resolve(null); return }
        const requestedUsername = normalizeUsername(username)
        if (!requestedUsername) { resolve(null); return }

        let settled = false
        const timer = setTimeout(() => {
          if (settled) return
          socket.off('user_public_keys_response', onKeys)
          resolve(null)
        }, timeoutMs)

        const onKeys = (data: Record<string, unknown>) => {
          const responseUsername = normalizeUsername(String(data?.username ?? ''))
          if (responseUsername !== requestedUsername) return
          settled = true
          clearTimeout(timer)
          socket.off('user_public_keys_response', onKeys)
          resolve(data)
        }

        socket.on('user_public_keys_response', onKeys)
        socket.emit('get_user_public_keys', { username: requestedUsername })
      })
    },
    [socket]
  )

  const syncOwnKeysWithServer = useCallback(
    async (username: string): Promise<void> => {
      if (!socket) return
      const normalizedUsername = normalizeUsername(username)
      if (!normalizedUsername) return

       setCheckingKeyStatus('Checking key sync')

      let localKeys = await loadStoredKeys(normalizedUsername)

      if (!localKeys) {
        await generateAndStoreKeys(normalizedUsername)
        localKeys = await loadStoredKeys(normalizedUsername)
      }

      if (!localKeys) {
        setKeyStatus({ state: 'missing', detail: 'Local keys unavailable' })
        return
      }

      const serverKeysResponse = await requestUserPublicKeys(normalizedUsername, 5000)
      const serverKeys = (serverKeysResponse as Record<string, Record<string, string>> | null)
        ?.publicKeys

      if (!serverKeys) {
        uploadPublicKeys(normalizedUsername, localKeys)
        setKeyStatus({ state: 'syncing', detail: 'Public keys uploaded, waiting for server sync' })
        return
      }

      const signingMatches = serverKeys.signingPublicKey === localKeys.signing.publicKey
      const encryptionMatches = serverKeys.encryptionPublicKey === localKeys.encryption.publicKey

      if (!signingMatches || !encryptionMatches) {
        uploadPublicKeys(normalizedUsername, localKeys)
        setKeyStatus({ state: 'syncing', detail: 'Refreshing server public keys' })
        return
      }

      setKeyStatus({ state: 'ready', detail: 'Local keys ready and synced' })
    },
    [socket, requestUserPublicKeys, setCheckingKeyStatus, uploadPublicKeys]
  )

  const ensureOwnKeysReady = useCallback(
    async (username: string) => {
      const normalizedUsername = normalizeUsername(username)
      if (!normalizedUsername) return null

      setCheckingKeyStatus('Checking local key files')

      let localKeys: Awaited<ReturnType<typeof loadStoredKeys>> = null
      try {
        localKeys = await loadStoredKeys(normalizedUsername)
      } catch (e) {
        console.error('loadStoredKeys failed:', e)
        setKeyStatus({ state: 'error', detail: 'IPC error loading keys' })
        return null
      }
      if (!localKeys) {
        try {
          await generateAndStoreKeys(normalizedUsername)
          localKeys = await loadStoredKeys(normalizedUsername)
        } catch {
          setKeyStatus({ state: 'error', detail: 'Failed to generate local keys' })
          return null
        }
      }

      if (localKeys) {
        uploadPublicKeys(normalizedUsername, localKeys)
        setKeyStatus({ state: 'local-only', detail: 'Local keys available' })
      } else {
        setKeyStatus({ state: 'missing', detail: 'Local keys unavailable' })
      }

      return localKeys
    },
    [setCheckingKeyStatus, uploadPublicKeys]
  )

  useEffect(() => {
    const newSocket = io(SERVER_URL, {
      autoConnect: false,
      withCredentials: true,
      transports: ['websocket', 'polling'],
    })

    setSocket(newSocket)

    newSocket.on('connect', () => {
      setIsConnected(true)
      setCheckingKeyStatus('Connected, checking key sync')
      newSocket.emit('get_online_users')
    })
    newSocket.on('disconnect', () => {
      setIsConnected(false)
      setKeyStatus((current) =>
        current.state === 'ready' || current.state === 'local-only'
          ? { state: 'local-only', detail: 'Local keys available, server offline' }
          : current
      )
    })
    newSocket.on('connect_error', (err: Error) => console.error('Connection error:', err.message))
    newSocket.on('error', (err: unknown) => console.error('Socket error:', err))
    newSocket.on('chat_history', () => {/* local history is the source of truth */})

    newSocket.on('inbox_data', (data: InboxItem[]) => {
      const currentUser = user?.username?.trim().toLowerCase()
      const normalized = (data || [])
        .filter((item) => {
          const contact = item.contact?.trim().toLowerCase()
          return Boolean(contact) && contact !== currentUser
        })
        .map((item) => ({
          ...item,
          last_message_preview: looksLikeCiphertext(item.last_message_preview)
            ? '[Encrypted message]'
            : item.last_message_preview,
        }))
      setInbox(normalized)
    })

    newSocket.on('online_users_data', (data: string[]) => setOnlineUsers(data))
    newSocket.on('all_contacts_data', (data: string[]) => setAllContacts(data))
    newSocket.on('user_status', () => newSocket.emit('get_online_users'))

    const savedToken = localStorage.getItem('mesez_token')
    const savedUsername = localStorage.getItem('mesez_username')
    if (savedToken && savedUsername) {
      newSocket.auth = { token: savedToken }
      newSocket.connect()
      setUser({ id: 'recovered', username: savedUsername })
      loadStoredKeys(savedUsername).then(async () => {
        try {
          await ensureOwnKeysReady(savedUsername)
          await syncOwnKeysWithServer(savedUsername)
        } catch (e) {
          console.error('Failed key sync during recovery:', e)
        }
      })
    } else {
      newSocket.connect()
    }

    return () => {
      newSocket.off('connect')
      newSocket.off('disconnect')
      newSocket.off('connect_error')
      newSocket.off('error')
      newSocket.off('chat_history')
      newSocket.off('inbox_data')
      newSocket.off('online_users_data')
      newSocket.off('all_contacts_data')
      newSocket.off('user_status')
      newSocket.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!socket || !user || !isConnected) return
    void ensureOwnKeysReady(user.username)
    void syncOwnKeysWithServer(user.username)
  }, [socket, user, isConnected, ensureOwnKeysReady, syncOwnKeysWithServer])

  // Handle incoming messages after auth state is available
  useEffect(() => {
    if (!socket || !user) return

    const onDirectMessage = async (msg: Record<string, unknown>) => {
      const mapped = mapServerMessage(msg)
      const currentUserKey = normalizeUsername(user.username)
      const fromKey = normalizeUsername(mapped.from)
      const toKey = normalizeUsername(mapped.to)

      if (!mapped.id || !mapped.timestamp || !fromKey || !toKey) return
      if (toKey !== currentUserKey && fromKey !== currentUserKey) return

      if (mapped.encrypted && mapped.iv) {
        try {
          const myKeys = await ensureOwnKeysReady(user.username)
          if (myKeys) {
            const senderPublicKeyFromPayload =
              typeof mapped.sender_encryption_public_key === 'string'
                ? mapped.sender_encryption_public_key
                : ''

            let senderEncryptionPublicKey = senderPublicKeyFromPayload

            if (!senderEncryptionPublicKey) {
              const senderKeys = await requestUserPublicKeys(mapped.from, 5000)
              const pk = (senderKeys as Record<string, Record<string, string>> | null)
                ?.publicKeys?.encryptionPublicKey
              senderEncryptionPublicKey = pk ?? ''
            }

            if (senderEncryptionPublicKey) {
              mapped.content = await decryptMessage(
                mapped.content,
                mapped.iv,
                senderEncryptionPublicKey,
                myKeys.encryption.privateKey
              )
              mapped.encrypted = false
              mapped.iv = undefined
              mapped.sender_encryption_public_key = undefined
            } else {
              mapped.content = '[Encrypted message - sender key unavailable]'
              mapped.encrypted = false
              mapped.iv = undefined
              mapped.sender_encryption_public_key = undefined
            }
          } else {
            mapped.content = '[Encrypted message - local keys unavailable]'
            mapped.encrypted = false
            mapped.iv = undefined
            mapped.sender_encryption_public_key = undefined
          }
        } catch {
          mapped.content = '[Encrypted message - decryption failed]'
          mapped.encrypted = false
          mapped.iv = undefined
          mapped.sender_encryption_public_key = undefined
          void syncOwnKeysWithServer(user.username)
        }
      } else if (looksLikeCiphertext(mapped.content)) {
        mapped.content = '[Encrypted message - metadata missing]'
      }

      await saveMessageLocally(user.username, mapped)
      await loadInbox()
      socket.emit('message_delivered_ack', { msgId: mapped.id })
      setMessages((prev) => {
        if (prev.find((m) => m.id === mapped.id)) return prev
        return [...prev, mapped]
      })
    }

    socket.on('direct_message', onDirectMessage)
    return () => { socket.off('direct_message', onDirectMessage) }
  }, [socket, user, ensureOwnKeysReady, requestUserPublicKeys, loadInbox, syncOwnKeysWithServer])

  const login = useCallback(
    (username: string, password: string) => {
      return new Promise<void>((resolve, reject) => {
        if (!socket) return reject(new Error('No socket connection'))

        socket.emit('login', { username, password })

        const onSuccess = async (data: { token: string; username: string }) => {
          try {
            localStorage.setItem('mesez_token', data.token)
            localStorage.setItem('mesez_username', data.username)
            socket.auth = { token: data.token }
            setUser({ id: 'loggedin', username: data.username })
            await ensureOwnKeysReady(data.username)
            await syncOwnKeysWithServer(data.username)
            resolve()
          } catch (err) {
            reject(err instanceof Error ? err.message : 'Login process failed')
          } finally {
            cleanup()
          }
        }

        const onError = (err: Error) => { reject(err.message || 'Login failed'); cleanup() }

        const cleanup = () => {
          socket.off('login_success', onSuccess)
          socket.off('error', onError)
        }

        socket.on('login_success', onSuccess)
        socket.on('error', onError)
      })
    },
    [socket, ensureOwnKeysReady, syncOwnKeysWithServer]
  )

  const register = useCallback(
    (username: string, password: string) => {
      return new Promise<void>((resolve, reject) => {
        if (!socket) return reject(new Error('No socket connection'))
        const id = uuidv4()
        socket.emit('register', { id, username, password })

        const onSuccess = async () => {
          try {
            const normalizedUsername = normalizeUsername(username)
            await generateAndStoreKeys(normalizedUsername)
            const localKeys = await loadStoredKeys(normalizedUsername)
            if (!localKeys) {
              throw new Error('Failed to persist generated keys locally')
            }
            socket.emit('upload_public_keys', {
              userId: id,
              username: normalizedUsername,
              signingPublicKey: localKeys.signing.publicKey,
              encryptionPublicKey: localKeys.encryption.publicKey,
              format: localKeys.format,
            })
            resolve()
          } catch (err) {
            reject(err instanceof Error ? err.message : 'Failed to generate keys')
          } finally {
            cleanup()
          }
        }

        const onError = (err: Error) => { reject(err.message || 'Registration failed'); cleanup() }

        const cleanup = () => {
          socket.off('register_success', onSuccess)
          socket.off('error', onError)
        }

        socket.on('register_success', onSuccess)
        socket.on('error', onError)
      })
    },
    [socket]
  )

  const logout = useCallback(() => {
    localStorage.removeItem('mesez_token')
    localStorage.removeItem('mesez_username')
    setUser(null)
    setMessages([])
    setInbox([])
    setOnlineUsers([])
    setAllContacts([])
    if (socket) {
      socket.auth = {}
      socket.disconnect()
      socket.connect()
    }
  }, [socket])

  const sendMessage = useCallback(
    async (to: string, content: string) => {
      if (!socket || !user) return

      let encryptedContent = content
      let iv: string | undefined
      let senderEncryptionPublicKey: string | undefined

      const myKeys = await ensureOwnKeysReady(user.username)
      if (!myKeys) {
        alert('Encryption error: failed to create local keys. Message was NOT sent.')
        return
      }

      // Key sync is best-effort — don't let a server timeout block sending.
      try {
        await syncOwnKeysWithServer(user.username)
      } catch (syncErr) {
        console.warn('Key sync skipped:', syncErr)
      }

      const recipientKeys = await requestUserPublicKeys(to, 5000)
      if (!recipientKeys) {
        alert(
          `Cannot send message: Public keys for user "${to}" not found. The user may need to log in to generate keys.`
        )
        return
      }

      const recipientPublicKeys = (recipientKeys as Record<string, Record<string, string>>)
        ?.publicKeys
      if (!recipientPublicKeys?.encryptionPublicKey) {
        alert(
          `Cannot send message: Encryption key for user "${to}" not found. The user may need to log in to generate keys.`
        )
        return
      }

      try {
        const result = await encryptMessage(
          content,
          recipientPublicKeys.encryptionPublicKey,
          myKeys.encryption.privateKey
        )
        encryptedContent = result.encryptedContent
        iv = result.iv
        senderEncryptionPublicKey = myKeys.encryption.publicKey
      } catch (encErr) {
        console.error('encryptMessage failed:', encErr)
        alert(`Failed to encrypt message. Message was NOT sent.\n${encErr instanceof Error ? encErr.message : String(encErr)}`)
        return
      }

      const msg: Message = {
        id: uuidv4(),
        from: user.username,
        to,
        content: encryptedContent,
        timestamp: new Date().toISOString(),
        status: 'sent',
        encrypted: true,
        iv,
        sender_encryption_public_key: senderEncryptionPublicKey,
      }

      const displayMsg = { ...msg, content }
      setMessages((prev) => [...prev, displayMsg])

      await saveMessageLocally(user.username, displayMsg)
      await loadInbox()

      try {
        const fragments = await fragmentMessage(msg as unknown as Record<string, unknown> & { to: string })
        fragments.forEach((fragment) => socket.emit('fragment', fragment))
        socket.emit('get_inbox')
      } catch {
        socket.emit('message', msg)
        socket.emit('get_inbox')
      }
    },
    [socket, user, ensureOwnKeysReady, requestUserPublicKeys, loadInbox, syncOwnKeysWithServer]
  )

  return (
    <SocketContext.Provider
      value={{
        socket,
        user,
        isConnected,
        keyStatus,
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
  )
}
