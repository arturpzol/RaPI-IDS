// Runs before first paint so the panel never flashes the wrong palette.
// Lives in its own file rather than inline in index.html so the Content-Security
// Policy can forbid inline script outright instead of carrying a hash that would
// have to be kept in step with this code.
// The storage key is shared with app/core/theme.ts - keep the two in step.
(function () {
  var mode = 'system';
  try { mode = localStorage.getItem('rapi-theme') || 'system'; } catch (e) {}
  var resolved = mode === 'light' || mode === 'dark'
    ? mode
    : (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.dataset.theme = resolved;
})();
