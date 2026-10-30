import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// 운영에서는 FastAPI가 dist/(index.html + /assets/*)를 그대로 서빙한다
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: { outDir: 'dist', assetsDir: 'assets', chunkSizeWarningLimit: 700 },
  server: { proxy: { '/api': 'http://127.0.0.1:8765' } },
})
