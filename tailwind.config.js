
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./public/**/*.{html,js}"],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#0a0a0f',
        'bg-secondary': '#1a1a24',
        'bg-tertiary': '#242438',
        'text-primary': '#ffffff',
        'text-secondary': '#b4b4c7',
        'accent-neon': '#00ff88',
        'accent-purple': '#8b5cf6',
        'accent-blue': '#3b82f6',
        'border-color': '#2d2d42',
      }
    },
  },
  plugins: [],
}
