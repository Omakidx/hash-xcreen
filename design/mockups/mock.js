/* Theme switch for the mockups only (the app has its own setting). Dark is the default. */
(function () {
  var KEY = 'hx-mock-theme', root = document.documentElement, t = null;
  try {
    t = new URLSearchParams(location.search).get('theme') || localStorage.getItem(KEY);
  } catch (e) { /* storage can be blocked on file:// */ }
  if (!/^(dark|light|system)$/.test(t || '')) t = 'dark';
  root.setAttribute('data-theme', t);
  document.addEventListener('DOMContentLoaded', function () {
    var sel = document.getElementById('theme');
    if (!sel) return;
    sel.value = t;
    sel.addEventListener('change', function () {
      root.setAttribute('data-theme', sel.value);
      try { localStorage.setItem(KEY, sel.value); } catch (e) { /* ignore */ }
    });
  });
})();
