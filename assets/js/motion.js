// Прогрессивные улучшения: scroll-reveal, состояние шапки, spotlight на карточках.
// Всё необязательное: без этого скрипта сайт полностью работает и виден —
// CSS прячет элементы только при наличии класса .js у <html>.
(function () {
  'use strict';
  var docEl = document.documentElement;
  docEl.classList.add('js');

  var reduced = false;
  try { reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) {}

  /* Шапка: подложка и hairline появляются после начала прокрутки */
  var header = document.querySelector('header.site');
  function headerState() {
    if (!header) return;
    header.classList.toggle('scrolled', (window.scrollY || 0) > 8);
  }
  headerState();
  window.addEventListener('scroll', headerState, { passive: true });

  /* Spotlight: карточка следит за курсором через CSS-переменные --mx/--my.
     На тач-устройствах и при reduced-motion ничего не делаем —
     статичное свечение уже описано в CSS по :hover. */
  var finePointer = false;
  try { finePointer = window.matchMedia('(pointer: fine)').matches; } catch (e) {}
  if (finePointer && !reduced) {
    document.addEventListener('pointermove', function (e) {
      var card = e.target && e.target.closest ? e.target.closest('.card') : null;
      if (!card) return;
      var r = card.getBoundingClientRect();
      card.style.setProperty('--mx', ((e.clientX - r.left) / r.width * 100).toFixed(1) + '%');
      card.style.setProperty('--my', ((e.clientY - r.top) / r.height * 100).toFixed(1) + '%');
    }, { passive: true });
  }

  /* Scroll-reveal: помечаем блоки и раскрываем каскадом при появлении.
     Внутри сетки элементы получают задержку по порядку — эффект «волны». */
  function markReveals() {
    var targets = document.querySelectorAll(
      'main .section:not(.hero), .apps .card, .legal, .support-form, ' +
      '.section .feat, .section .step, .section .shot'
    );
    for (var i = 0; i < targets.length; i++) {
      targets[i].classList.add('reveal');
    }
    // Каскад внутри каждой сетки/секции: индекс среди соседей своего родителя
    var grids = document.querySelectorAll('.grid');
    for (var g = 0; g < grids.length; g++) {
      var kids = grids[g].children;
      for (var k = 0; k < kids.length; k++) {
        if (kids[k].classList.contains('reveal')) {
          kids[k].style.setProperty('--rd', Math.min(k * 70, 420) + 'ms');
        }
      }
    }
  }

  function watchReveals() {
    var items = document.querySelectorAll('.reveal');
    if (!('IntersectionObserver' in window) || reduced) {
      for (var i = 0; i < items.length; i++) items[i].classList.add('in');
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      for (var j = 0; j < entries.length; j++) {
        if (entries[j].isIntersecting) {
          entries[j].target.classList.add('in');
          io.unobserve(entries[j].target);
        }
      }
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    for (var i = 0; i < items.length; i++) io.observe(items[i]);
  }

  function start() {
    markReveals();
    watchReveals();
    // Контент, догрузившийся позже (например, после langchange), не прячем
    window.addEventListener('langchange', function () {
      var hidden = document.querySelectorAll('.reveal:not(.in)');
      for (var i = 0; i < hidden.length; i++) {
        var r = hidden[i].getBoundingClientRect();
        if (r.top < window.innerHeight) hidden[i].classList.add('in');
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
