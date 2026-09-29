// Applies the saved (or system) colour theme before first paint. External file: the CSP forbids inline scripts.
try {
  var t = localStorage.getItem('sn-theme')
  if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches)) document.documentElement.classList.add('dark')
} catch (e) { /* storage unavailable */ }
