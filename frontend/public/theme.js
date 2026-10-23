// Applies the operator's saved theme before first paint (external file: the CSP allows no inline script).
(function () {
    var m = document.cookie.match(/(?:^|; )dnsone_theme=(light|dark)/);
    if (m) document.documentElement.dataset.theme = m[1];
})();
