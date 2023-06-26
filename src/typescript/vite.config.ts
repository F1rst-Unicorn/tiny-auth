import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import checker from 'vite-plugin-checker'

export default defineConfig({
  base: "",
  clearScreen: false,
  plugins: [react(),
    checker({
      typescript: true,
    }),
  ],
})
