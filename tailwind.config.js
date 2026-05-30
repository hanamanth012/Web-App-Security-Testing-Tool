/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        neon: {
          green: '#00ff41',
          lime: '#39ff14',
          dark: '#00cc33',
        },
        cyber: {
          black: '#0a0a0a',
          dark: '#0d0d0d',
          gray: '#1a1a1a',
          border: '#1f1f1f',
          card: '#111111',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        display: ['Orbitron', 'sans-serif'],
      },
      animation: {
        'pulse-green': 'pulseGreen 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanLine 2s linear infinite',
        'flicker': 'flicker 3s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'matrix': 'matrix 20s linear infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.5s ease-out',
      },
      keyframes: {
        pulseGreen: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.4 },
        },
        scanLine: {
          '0%': { top: '0%' },
          '100%': { top: '100%' },
        },
        flicker: {
          '0%, 95%, 100%': { opacity: 1 },
          '96%, 99%': { opacity: 0.8 },
        },
        glow: {
          'from': { textShadow: '0 0 5px #00ff41, 0 0 10px #00ff41' },
          'to': { textShadow: '0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 30px #00ff41' },
        },
        slideIn: {
          'from': { transform: 'translateX(-10px)', opacity: 0 },
          'to': { transform: 'translateX(0)', opacity: 1 },
        },
        fadeIn: {
          'from': { opacity: 0, transform: 'translateY(10px)' },
          'to': { opacity: 1, transform: 'translateY(0)' },
        },
      },
      boxShadow: {
        'neon': '0 0 5px #00ff41, 0 0 10px #00ff41, 0 0 20px #00ff41',
        'neon-sm': '0 0 3px #00ff41, 0 0 6px #00ff41',
        'neon-lg': '0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 40px #00ff41',
        'card': '0 0 20px rgba(0, 255, 65, 0.05)',
      }
    },
  },
  plugins: [],
}
