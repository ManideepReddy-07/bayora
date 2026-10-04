/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: { extend: { colors: { bayora: { bg: '#0B0F14', surface: '#111821', card: '#161F2B', border: '#273344', primary: '#7C5CFF', success: '#36B37E', warning: '#FFB020', danger: '#FF5C65', text: '#F5F7FA', muted: '#A4B0C0' } } } },
  plugins: [],
}
