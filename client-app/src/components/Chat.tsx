import React, { useEffect, useState, useRef } from 'react'
import { useSocket } from '../context/SocketContext'
import { Send, LogOut, User as UserIcon, MessageSquare, Plus, X, Search } from 'lucide-react'
import { format } from 'date-fns'

export const Chat: React.FC = () => {
  const { user, messages, sendMessage, logout, loadInbox, loadChatHistory, inbox, onlineUsers, allContacts, keyStatus } =
    useSocket()
  const [input, setInput] = useState('')
  const [activeContact, setActiveContact] = useState<string | null>(null)
  const [showNewChat, setShowNewChat] = useState(false)
  const [newChatUser, setNewChatUser] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const keyStatusTone = {
    ready: 'text-green-400 bg-green-500/10 border-green-500/15',
    syncing: 'text-amber-300 bg-amber-500/10 border-amber-500/15',
    checking: 'text-sky-300 bg-sky-500/10 border-sky-500/15',
    'local-only': 'text-blue-300 bg-blue-500/10 border-blue-500/15',
    missing: 'text-red-400 bg-red-500/10 border-red-500/15',
    error: 'text-red-400 bg-red-500/10 border-red-500/15',
  }[keyStatus.state]

  const keyDotTone = {
    ready: 'bg-green-500',
    syncing: 'bg-amber-400',
    checking: 'bg-sky-400',
    'local-only': 'bg-blue-400',
    missing: 'bg-red-500',
    error: 'bg-red-500',
  }[keyStatus.state]

  useEffect(() => { loadInbox() }, [loadInbox])

  useEffect(() => {
    if (activeContact) loadChatHistory(activeContact)
  }, [activeContact, loadChatHistory])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || !activeContact) return
    sendMessage(activeContact, input)
    setInput('')
  }

  const handleNewChat = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newChatUser.trim()) return
    setActiveContact(newChatUser.trim())
    setShowNewChat(false)
    setNewChatUser('')
  }

  const filteredInbox = inbox.filter((conv) =>
    conv.contact.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const isContactOnline = (contact: string) => onlineUsers.includes(contact)

  const visibleMessages = activeContact
    ? messages.filter((msg) => {
        const active = activeContact.toLowerCase()
        const from = (msg.from || '').toLowerCase()
        const to = (msg.to || '').toLowerCase()
        const me = (user?.username || '').toLowerCase()
        return (from === me && to === active) || (from === active && to === me)
      })
    : []

  return (
    <div className="flex h-screen w-full bg-surface-950 text-white overflow-hidden">
      {/* Sidebar */}
      <div className="w-80 bg-surface-900/80 border-r border-white/6 flex flex-col animate-slide-left">
        {/* User header */}
        <div className="p-4 border-b border-white/6 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-primary-700 rounded-xl flex items-center justify-center shadow-md shadow-primary-500/20">
              <span className="font-bold text-sm">{user?.username.substring(0, 2).toUpperCase()}</span>
            </div>
            <div>
              <span className="font-semibold text-sm">{user?.username}</span>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-[11px] text-surface-200/50">Online</span>
              </div>
              <div className={`mt-2 inline-flex items-center gap-2 rounded-lg border px-2.5 py-1 text-[11px] ${keyStatusTone}`}>
                <span className={`h-2 w-2 rounded-full ${keyDotTone}`} />
                {keyStatus.detail}
              </div>
            </div>
          </div>
          <button
            onClick={logout}
            className="p-2 rounded-lg text-surface-200/40 hover:text-white hover:bg-white/5 transition-all"
            title="Logout"
          >
            <LogOut size={18} />
          </button>
        </div>

        {/* Search + New Chat */}
        <div className="p-3 space-y-2">
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-surface-200/30" />
            <input
              type="text"
              placeholder="Search conversations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-white/5 border border-white/6 rounded-xl text-sm text-white placeholder-surface-200/30 focus:outline-none focus:ring-1 focus:ring-primary-500/30 transition-all"
            />
          </div>
          <button
            onClick={() => setShowNewChat(true)}
            className="w-full flex items-center justify-center gap-2 bg-primary-600/15 hover:bg-primary-600/25 text-primary-400 py-2.5 rounded-xl transition-all text-sm font-medium border border-primary-500/10"
          >
            <Plus size={16} /> New Chat
          </button>
        </div>

        {/* Conversation list */}
        <div className="flex-1 overflow-y-auto">
          {filteredInbox.length > 0 && (
            <div className="px-4 py-2 text-xs font-semibold text-surface-200/50 uppercase tracking-wider">
              Conversations
            </div>
          )}
          {filteredInbox.map((conv, i) => (
            <div
              key={conv.contact}
              onClick={() => setActiveContact(conv.contact)}
              className={`p-3.5 mx-2 my-0.5 rounded-xl cursor-pointer transition-all duration-200 animate-fade-in ${
                activeContact === conv.contact
                  ? 'bg-primary-600/15 border border-primary-500/20'
                  : 'hover:bg-white/4 border border-transparent'
              }`}
              style={{ animationDelay: `${i * 50}ms` }}
            >
              <div className="flex items-center gap-3">
                <div className="relative flex-shrink-0">
                  <div className="w-10 h-10 bg-surface-700 rounded-xl flex items-center justify-center">
                    <UserIcon size={18} className="text-surface-200/50" />
                  </div>
                  <span
                    className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-surface-900 ${
                      isContactOnline(conv.contact) ? 'bg-green-500' : 'bg-surface-200/20'
                    }`}
                  />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between items-center mb-0.5">
                    <span className="font-medium text-sm text-surface-100">{conv.contact}</span>
                    <span className="text-[10px] text-surface-200/40">
                      {format(new Date(conv.last_timestamp), 'HH:mm')}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <p className="text-xs text-surface-200/40 truncate pr-3">
                      {conv.last_message_preview}
                    </p>
                    {conv.unread_count > 0 && (
                      <span className="flex-shrink-0 inline-flex items-center justify-center w-5 h-5 text-[10px] font-bold bg-primary-600 text-white rounded-full">
                        {conv.unread_count}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}

          {/* Registered users not in inbox */}
          {allContacts.filter(
            (u) =>
              !inbox.some((c) => c.contact === u) &&
              u.toLowerCase().includes(searchQuery.toLowerCase())
          ).length > 0 && (
            <div className="mt-4">
              <div className="px-4 py-2 text-xs font-semibold text-surface-200/50 uppercase tracking-wider">
                Registered Users
              </div>
              {allContacts
                .filter(
                  (u) =>
                    !inbox.some((c) => c.contact === u) &&
                    u.toLowerCase().includes(searchQuery.toLowerCase())
                )
                .map((username, i) => {
                  const isOnline = isContactOnline(username)
                  return (
                    <div
                      key={username}
                      onClick={() => setActiveContact(username)}
                      className={`p-3.5 mx-2 my-0.5 rounded-xl cursor-pointer transition-all duration-200 animate-fade-in ${
                        activeContact === username
                          ? 'bg-primary-600/15 border border-primary-500/20'
                          : 'hover:bg-white/4 border border-transparent'
                      }`}
                      style={{ animationDelay: `${i * 50}ms` }}
                    >
                      <div className="flex items-center gap-3">
                        <div className="relative flex-shrink-0">
                          <div className="w-10 h-10 bg-surface-700 rounded-xl flex items-center justify-center">
                            <UserIcon size={18} className="text-surface-200/50" />
                          </div>
                          <span
                            className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-surface-900 ${
                              isOnline ? 'bg-green-500' : 'bg-surface-200/30'
                            }`}
                          />
                        </div>
                        <div className="flex-1 min-w-0">
                          <span className="font-medium text-sm text-surface-100">{username}</span>
                          <p className={`text-xs truncate ${isOnline ? 'text-green-400/70' : 'text-surface-200/30'}`}>
                            {isOnline ? 'Online now' : 'Offline'}
                          </p>
                        </div>
                      </div>
                    </div>
                  )
                })}
            </div>
          )}

          {filteredInbox.length === 0 &&
            allContacts.filter(
              (u) =>
                !inbox.some((c) => c.contact === u) &&
                u.toLowerCase().includes(searchQuery.toLowerCase())
            ).length === 0 && (
              <div className="p-8 text-center">
                <div className="w-12 h-12 bg-white/5 rounded-2xl flex items-center justify-center mx-auto mb-3">
                  <MessageSquare size={20} className="text-surface-200/30" />
                </div>
                <p className="text-surface-200/40 text-sm">No conversations found</p>
                <p className="text-surface-200/25 text-xs mt-1">Start a new chat!</p>
              </div>
            )}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col bg-surface-950">
        {activeContact ? (
          <>
            {/* Chat header */}
            <div className="px-6 py-4 border-b border-white/6 bg-surface-900/50 backdrop-blur-xl flex items-center gap-3">
              <div className="relative">
                <div className="w-10 h-10 bg-gradient-to-br from-primary-500/80 to-primary-700/80 rounded-xl flex items-center justify-center">
                  <UserIcon size={18} className="text-white" />
                </div>
                <span
                  className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-surface-900 ${
                    isContactOnline(activeContact) ? 'bg-green-500' : 'bg-surface-200/20'
                  }`}
                />
              </div>
              <div>
                <h3 className="font-semibold text-sm">{activeContact}</h3>
                <span
                  className={`text-xs ${
                    isContactOnline(activeContact) ? 'text-green-400' : 'text-surface-200/40'
                  }`}
                >
                  {isContactOnline(activeContact) ? 'Online' : 'Offline'}
                </span>
              </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-6 space-y-3">
              {visibleMessages.length === 0 && (
                <div className="h-full flex flex-col items-center justify-center text-surface-200/30">
                  <MessageSquare size={32} className="mb-2" />
                  <p className="text-sm">No messages yet. Say hello! 👋</p>
                </div>
              )}
              {visibleMessages.map((msg, i) => {
                const isMe = msg.from === user?.username
                return (
                  <div
                    key={msg.id || i}
                    className={`flex ${isMe ? 'justify-end' : 'justify-start'} ${
                      isMe ? 'animate-slide-right' : 'animate-slide-left'
                    }`}
                  >
                    <div
                      className={`max-w-[70%] rounded-2xl px-4 py-2.5 ${
                        isMe
                          ? 'bg-gradient-to-br from-primary-600 to-primary-700 text-white rounded-br-md shadow-lg shadow-primary-500/10'
                          : 'glass text-surface-100 rounded-bl-md'
                      }`}
                    >
                      <p className="text-sm leading-relaxed">{msg.content}</p>
                      <div
                        className={`text-[10px] mt-1 flex items-center gap-1 ${
                          isMe ? 'text-primary-200/60 justify-end' : 'text-surface-200/30'
                        }`}
                      >
                        {format(new Date(msg.timestamp), 'HH:mm')}
                        {isMe && msg.status && (
                          <span className="ml-0.5">
                            {msg.status === 'sent' && '✓'}
                            {msg.status === 'delivered' && '✓✓'}
                            {msg.status === 'read' && <span className="text-blue-300">✓✓</span>}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <form onSubmit={handleSend} className="p-4 border-t border-white/6 bg-surface-900/30">
              <div className="flex gap-3 items-center">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Type a message..."
                  className="flex-1 bg-white/5 border border-white/6 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/30 focus:border-primary-500/20 transition-all placeholder-surface-200/25"
                />
                <button
                  type="submit"
                  disabled={!input.trim()}
                  className="bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-white p-3 rounded-xl transition-all duration-300 disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-primary-500/15 hover:shadow-primary-500/25 hover:scale-105 active:scale-95"
                >
                  <Send size={18} />
                </button>
              </div>
            </form>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center relative">
            {showNewChat ? (
              <div className="w-full max-w-sm p-6 glass rounded-2xl animate-fade-in">
                <div className="flex justify-between items-center mb-5">
                  <h3 className="text-lg font-bold">Start New Chat</h3>
                  <button
                    onClick={() => setShowNewChat(false)}
                    className="p-1.5 rounded-lg hover:bg-white/5 text-surface-200/40 hover:text-white transition-all"
                  >
                    <X size={18} />
                  </button>
                </div>
                <form onSubmit={handleNewChat}>
                  <input
                    autoFocus
                    type="text"
                    placeholder="Enter username"
                    className="w-full px-4 py-3 bg-surface-900/80 border border-white/8 rounded-xl text-white text-sm mb-4 focus:outline-none focus:ring-2 focus:ring-primary-500/30 placeholder-surface-200/30 transition-all"
                    value={newChatUser}
                    onChange={(e) => setNewChatUser(e.target.value)}
                  />
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setShowNewChat(false)}
                      className="px-4 py-2 text-sm text-surface-200/50 hover:text-white rounded-lg transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-5 py-2 bg-gradient-to-r from-primary-600 to-primary-500 text-white text-sm font-medium rounded-xl hover:from-primary-500 hover:to-primary-400 transition-all shadow-md shadow-primary-500/15"
                    >
                      Start Chat
                    </button>
                  </div>
                </form>
              </div>
            ) : (
              <div className="animate-fade-in flex flex-col items-center">
                <div className="w-20 h-20 glass rounded-3xl flex items-center justify-center mb-5">
                  <MessageSquare size={32} className="text-primary-400/60" />
                </div>
                <h2 className="text-xl font-semibold text-surface-200/80 mb-1">Your Messages</h2>
                <p className="text-sm text-surface-200/35">Select a conversation or start a new chat</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
