/* Household Skills Marketplace - front-end behaviour (no inline scripts; CSP-safe) */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* ---- password requirements checklist (mirrors security.py) ---- */
  $$("[data-pw-checklist]").forEach(function (box) {
    var cfg = JSON.parse(box.getAttribute("data-rules"));
    var form = box.closest("form");
    var pw = $("input[name=password]", form), conf = $("input[name=confirm]", form);
    var email = $("input[name=email]", form), name = $("input[name=full_name]", form);
    var fixedEmail = box.getAttribute("data-email") || "", fixedName = box.getAttribute("data-name") || "";
    var items = {}; $$("li", box).forEach(function (li) { items[li.getAttribute("data-rule")] = li; });
    var meter = $(".meter b", box.parentNode), match = $(".match", form);

    function personalBits() {
      var e = ((email && email.value) || fixedEmail).split("@")[0], n = (name && name.value) || fixedName;
      return (e + " " + n).split(/[\s._@+-]+/).filter(function (b) { return b.length >= 3; });
    }
    function evaluate() {
      var v = pw.value, low = v.toLowerCase();
      var res = {
        length: v.length >= cfg.min, upper: /[A-Z]/.test(v), lower: /[a-z]/.test(v), digit: /\d/.test(v),
        special: /[^A-Za-z0-9\s]/.test(v), nospace: v.length > 0 && !/\s/.test(v),
        common: !cfg.common.some(function (c) { return low.indexOf(c) > -1; }),
        personal: !personalBits().some(function (b) { return low.indexOf(b.toLowerCase()) > -1; })
      };
      var passed = 0, all = true;
      Object.keys(items).forEach(function (k) {
        items[k].classList.toggle("ok", !!res[k]);
        if (res[k]) passed++; else all = false;
      });
      if (meter) meter.className = v ? "s" + Math.max(1, Math.ceil(passed / Object.keys(items).length * 4)) : "";
      pw.setCustomValidity(all ? "" : "Your password does not meet all of the requirements yet.");
      if (conf) {
        var same = conf.value === v;
        conf.setCustomValidity(same ? "" : "Passwords do not match.");
        if (match) { match.textContent = conf.value ? (same ? "Passwords match." : "Passwords do not match yet.") : ""; match.className = "match " + (same ? "good" : "bad"); }
      }
    }
    [pw, conf, email, name].forEach(function (el) { if (el) el.addEventListener("input", evaluate); });
    evaluate();
  });

  /* ---- show / hide password ---- */
  $$("[data-toggle-pw]").forEach(function (b) {
    b.addEventListener("click", function () {
      var i = b.parentNode.querySelector("input");
      var show = i.type === "password"; i.type = show ? "text" : "password";
      b.textContent = show ? "Hide" : "Show"; b.setAttribute("aria-pressed", String(show));
    });
  });

  /* ---- copy link buttons ---- */
  $$("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var input = document.getElementById(b.getAttribute("data-copy"));
      input.select();
      var done = function () { var t = b.textContent; b.textContent = "Copied!"; setTimeout(function () { b.textContent = t; }, 1600); };
      if (navigator.clipboard) navigator.clipboard.writeText(input.value).then(done, function () { document.execCommand("copy"); done(); });
      else { document.execCommand("copy"); done(); }
    });
  });

  /* ---- confirm destructive actions, prevent double submit, live character counters ---- */
  $$("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault(); });
  });
  $$("form").forEach(function (f) {
    f.addEventListener("submit", function () {
      if (!f.checkValidity()) return;
      setTimeout(function () { $$("button[type=submit]", f).forEach(function (b) { b.disabled = true; }); }, 0);
    });
  });
  $$("textarea[maxlength]").forEach(function (t) {
    var c = document.createElement("div"); c.className = "hint"; t.parentNode.appendChild(c);
    var up = function () { c.textContent = t.value.length + " / " + t.maxLength + " characters"; };
    t.addEventListener("input", up); up();
  });
  /* ---- 6-digit code input: digits only ---- */
  $$("input[data-code]").forEach(function (i) { i.addEventListener("input", function () { i.value = i.value.replace(/\D/g, "").slice(0, 6); }); });
})();
document.querySelectorAll("[data-print]").forEach(function (b) { b.addEventListener("click", function () { window.print(); }); });
window.addEventListener("pageshow", function () { document.querySelectorAll("button[type=submit]:disabled").forEach(function (b) { b.disabled = false; }); });
