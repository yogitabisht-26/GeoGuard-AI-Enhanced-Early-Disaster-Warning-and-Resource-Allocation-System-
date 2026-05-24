// ═══════════════════════════════════════════
// GeoGuard Theme System — Dark / Light Mode
// ═══════════════════════════════════════════
(function(){
  var DARK = {
    '--bg':'#050a08','--card':'#0a1410','--card2':'#0f1c16',
    '--border':'#162b1e','--border2':'#1e3d2a',
    '--text':'#e8f5ee','--muted':'#5a8068','--muted2':'#3d5c4a',
    '--green':'#4ade80','--green2':'#22c55e',
    '--red':'#f87171','--orange':'#fb923c','--yellow':'#fbbf24','--blue':'#60a5fa'
  };
  var LIGHT = {
    '--bg':'#f0fdf4','--card':'#ffffff','--card2':'#f9fafb',
    '--border':'#d1fae5','--border2':'#a7f3d0',
    '--text':'#064e3b','--muted':'#4b7a5c','--muted2':'#6b9e7d',
    '--green':'#16a34a','--green2':'#15803d',
    '--red':'#dc2626','--orange':'#d97706','--yellow':'#b45309','--blue':'#1d4ed8'
  };

  function applyTheme(mode){
    var vars = mode === 'light' ? LIGHT : DARK;
    var root = document.documentElement;
    Object.keys(vars).forEach(function(k){ root.style.setProperty(k, vars[k]); });
    // Update button icon on ALL pages
    document.querySelectorAll('.theme-toggle-btn').forEach(function(btn){
      btn.textContent = mode === 'light' ? '☀️' : '🌙';
      btn.title = mode === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode';
    });
    // Store
    localStorage.setItem('gg_theme', mode);
    // Body class for any extra CSS overrides
    if(mode === 'light'){ document.body.classList.add('light'); }
    else { document.body.classList.remove('light'); }
  }

  window.toggleTheme = function(){
    var cur = localStorage.getItem('gg_theme') || 'dark';
    applyTheme(cur === 'light' ? 'dark' : 'light');
  };

  window.applyTheme = applyTheme;

  // Apply on page load immediately (before DOMContentLoaded)
  var saved = localStorage.getItem('gg_theme') || 'dark';
  // Set CSS vars immediately to prevent flash
  var vars = saved === 'light' ? LIGHT : DARK;
  var style = document.createElement('style');
  style.id = 'gg-theme-vars';
  var cssVars = ':root{' + Object.keys(vars).map(function(k){ return k+':'+vars[k]; }).join(';') + '}';
  style.textContent = cssVars;
  document.head.appendChild(style);

  // After DOM ready, apply body class and button
  document.addEventListener('DOMContentLoaded', function(){
    applyTheme(saved);
  });
})();
