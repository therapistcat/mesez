import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import electron from 'vite-plugin-electron'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const extraAllowedHosts = (env.VITE_ALLOWED_HOSTS || '')
    .split(',')
    .map((h) => h.trim())
    .filter(Boolean)

  const allowedHosts = Array.from(
    new Set(['localhost', '127.0.0.1', ...extraAllowedHosts])
  )

  return {
    plugins: [
      react(),
      tailwindcss(),
      electron([
        {
          entry: 'electron/main.ts',
        },
        {
          entry: 'electron/preload.ts',
          onstart(options) {
            options.reload()
          },
        },
      ]),
    ],
    server: {
      allowedHosts,
      watch: {
        ignored: ['**/.keys/**', '**/.messages/**', '**/dist-electron/**'],
      },
    },
  }
})
