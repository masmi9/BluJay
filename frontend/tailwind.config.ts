import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base: '#060d1f',
          surface: '#0b1530',
          elevated: '#101e40',
          border: '#1a2d55',
        },
        accent: {
          DEFAULT: '#2563eb',
          hover: '#3b82f6',
          muted: '#2563eb20',
        },
        severity: {
          critical: '#f43f5e',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
          info: '#3b82f6',
        },
        method: {
          GET: '#22c55e',
          POST: '#3b82f6',
          PUT: '#eab308',
          DELETE: '#f43f5e',
          PATCH: '#f97316',
          OPTIONS: '#8b5cf6',
          HEAD: '#6b7280',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config
