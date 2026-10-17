// Переключатель языка сайта: RU/EN.
//
// Механика: тексты обоих языков лежат в разметке рядом (data-lang="ru" /
// data-lang="en"), а видимость решает CSS от <html lang>. Этот скрипт не
// переписывает тексты, а только меняет lang и запоминает выбор. Без JS
// страница остаётся на русском — это её обычное состояние в файле.
(function () {
  'use strict';
  var KEY = 'actl-lang';
  var current = 'ru';

  function detect() {
    // По умолчанию — русский; EN остаётся только за явным выбором пользователя
    // (сохранённое значение в localStorage). Язык браузера не учитываем:
    // страница всегда открывается на русском.
    try {
      var saved = localStorage.getItem(KEY);
      if (saved === 'ru' || saved === 'en') return saved;
    } catch (e) {}
    return 'ru';
  }

  function apply(lang) {
    current = lang === 'en' ? 'en' : 'ru';
    document.documentElement.lang = current;
    if (document.body) {
      var t = document.body.getAttribute('data-title-' + current);
      if (t) document.title = t;
    }
    var input = document.querySelector('input[name="lang"]');
    if (input) input.value = current;
    var buttons = document.querySelectorAll('.lang-switch button');
    for (var i = 0; i < buttons.length; i++) {
      var on = buttons[i].getAttribute('data-set-lang') === current;
      buttons[i].classList.toggle('active', on);
      buttons[i].setAttribute('aria-pressed', on ? 'true' : 'false');
    }
    window.dispatchEvent(new CustomEvent('langchange', { detail: { lang: current } }));
  }

  // Кнопки живут в шапке. Разметку страниц не трогаем: один скрипт на все
  // страницы сам добавляет переключатель в .nav, поэтому новая страница
  // получает его одним <script>, без копипасты кнопок.
  function buildSwitch() {
    var nav = document.querySelector('header.site .nav');
    if (!nav || nav.querySelector('.lang-switch')) return;
    var box = document.createElement('div');
    box.className = 'lang-switch';
    box.setAttribute('role', 'group');
    box.setAttribute('aria-label', 'Язык / Language');
    var codes = ['ru', 'en'];
    for (var i = 0; i < codes.length; i++) {
      (function (code) {
        var b = document.createElement('button');
        b.type = 'button';
        b.textContent = code.toUpperCase();
        b.setAttribute('data-set-lang', code);
        b.addEventListener('click', function () {
          try { localStorage.setItem(KEY, code); } catch (e) {}
          apply(code);
        });
        box.appendChild(b);
      })(codes[i]);
    }
    nav.appendChild(box);
  }

  function start() {
    buildSwitch();
    apply(detect());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }

  window.siteLang = function () { return current; };
})();
