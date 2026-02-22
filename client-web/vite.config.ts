import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const extraAllowedHosts = (env.VITE_ALLOWED_HOSTS || '')
    .split(',')
    .map((host) => host.trim())
    .filter(Boolean)

  const allowedHosts = Array.from(
    new Set([
      'localhost',
      '127.0.0.1',
      '.ngrok-free.app',
      '.ngrok-free.dev',
      '.ngrok.app',
      '.devtunnels.ms',
      ...extraAllowedHosts,
    ])
  )

  return {
    plugins: [react(), tailwindcss()],
    server: {
      allowedHosts,
    },
  }
})
