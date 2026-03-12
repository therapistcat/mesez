import React, { useState } from 'react'
import { useSocket } from '../context/SocketContext'
import { MessageSquare, Loader2, Eye, EyeOff } from 'lucide-react'

export const Login: React.FC = () => {
  const { login, register, isConnected, keyStatus } = useSocket()
  const [isLogin, setIsLogin] = useState(true)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const keyStatusTone = {
    ready: 'bg-green-500/10 text-green-400',
    syncing: 'bg-amber-500/10 text-amber-300',
    checking: 'bg-sky-500/10 text-sky-300',
    'local-only': 'bg-blue-500/10 text-blue-300',
    missing: 'bg-red-500/10 text-red-400',
    error: 'bg-red-500/10 text-red-400',
  }[keyStatus.state]

  const keyDotTone = {
    ready: 'bg-green-500',
    syncing: 'bg-amber-400',
    checking: 'bg-sky-400',
    'local-only': 'bg-blue-400',
    missing: 'bg-red-500',
    error: 'bg-red-500',
  }[keyStatus.state]

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    setSuccess('')

    try {
      if (isLogin) {
        await login(username, password)
      } else {
        await register(username, password)
        setIsLogin(true)
        setSuccess('Account created! Sign in to continue.')
        setPassword('')
        setLoading(false)
        return
      }
    } catch (err: unknown) {
      setError(typeof err === 'string' ? err : String(err))
    } finally {
      if (isLogin) setLoading(false)
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen w-full bg-surface-950 relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 bg-primary-600/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-primary-400/8 rounded-full blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary-500/5 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md mx-4 animate-fade-in relative z-10">
        <div className="flex flex-col items-center mb-8">
          <div className="relative mb-5">
            <div className="w-16 h-16 bg-gradient-to-br from-primary-500 to-primary-700 rounded-2xl flex items-center justify-center shadow-lg shadow-primary-500/25 rotate-3 transition-transform hover:rotate-0 hover:scale-105">
              <MessageSquare size={28} className="text-white" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-5 h-5 bg-green-500 rounded-full border-[3px] border-surface-950" />
          </div>
          <h1 className="text-4xl font-bold tracking-tight gradient-text">mesez</h1>
          <p className="text-surface-200/60 mt-2 text-sm font-medium">
            {isLogin ? 'Welcome back! Sign in to continue.' : 'Create your account to get started.'}
          </p>
        </div>

        <div className="glass rounded-2xl p-8 shadow-2xl shadow-black/30">
          <div
            className={`flex items-center gap-2 mb-6 px-3 py-2 rounded-lg text-xs font-medium ${
              isConnected ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
            {isConnected ? 'Connected to server' : 'Not connected — start the server'}
          </div>

          <div className={`flex items-center gap-2 mb-6 px-3 py-2 rounded-lg text-xs font-medium ${keyStatusTone}`}>
            <span className={`w-2 h-2 rounded-full ${keyDotTone}`} />
            {keyStatus.detail}
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-xs font-semibold text-surface-200/70 mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 bg-surface-900/80 border border-white/8 rounded-xl text-white placeholder-surface-200/30 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-primary-500/30 transition-all duration-200"
                placeholder="Enter your username"
                autoComplete="username"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-surface-200/70 mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-3 pr-12 bg-surface-900/80 border border-white/8 rounded-xl text-white placeholder-surface-200/30 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-primary-500/30 transition-all duration-200"
                  placeholder="Enter your password"
                  autoComplete={isLogin ? 'current-password' : 'new-password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-surface-200/40 hover:text-white transition-colors"
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm animate-fade-in">
                {error}
              </div>
            )}
            {success && (
              <div className="p-3 rounded-xl bg-green-500/10 border border-green-500/20 text-green-400 text-sm animate-fade-in">
                {success}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !isConnected}
              className="w-full bg-gradient-to-r from-primary-600 to-primary-500 hover:from-primary-500 hover:to-primary-400 text-white font-semibold py-3 rounded-xl transition-all duration-300 flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-lg shadow-primary-500/20 hover:shadow-primary-500/30 hover:scale-[1.01] active:scale-[0.99]"
            >
              {loading ? (
                <Loader2 className="animate-spin" size={20} />
              ) : isLogin ? (
                'Sign In'
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-surface-200/50">
            {isLogin ? "Don't have an account? " : 'Already have an account? '}
            <button
              onClick={() => { setIsLogin(!isLogin); setError(''); setSuccess('') }}
              className="text-primary-400 hover:text-primary-300 font-semibold transition-colors"
            >
              {isLogin ? 'Sign up' : 'Sign in'}
            </button>
          </div>
        </div>

        <p className="text-center text-xs text-surface-200/25 mt-6">
          End-to-end messaging • Built with 💜
        </p>
      </div>
    </div>
  )
}
