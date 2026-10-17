(function(){
  var LABELS = {
    ru: { close: 'Закрыть', prev: 'Назад', next: 'Вперёд' },
    en: { close: 'Close', prev: 'Back', next: 'Next' }
  };
  function lang(){ return document.documentElement.lang === 'en' ? 'en' : 'ru'; }
  var gallery = document.querySelector('[data-gallery]');
  if(!gallery) return;
  function captionOf(btn){
    return btn.getAttribute('data-caption-' + lang())
        || btn.getAttribute('data-caption-ru')
        || btn.querySelector('img').getAttribute('alt') || '';
  }
  var items = [];
  function collect(){
    items = Array.prototype.slice.call(gallery.querySelectorAll('.shot-btn')).map(function(btn){
      return { src: btn.querySelector('img').getAttribute('src'), cap: captionOf(btn) };
    });
  }
  collect();
  var box = document.createElement('div');
  box.className = 'lightbox'; box.id = 'lightbox'; box.setAttribute('aria-hidden','true');
  box.innerHTML = '<div class="lb-backdrop" data-lb-close></div>'
    + '<button class="lb-close" data-lb-close aria-label="' + LABELS[lang()].close + '">✕</button>'
    + '<button class="lb-btn lb-prev" aria-label="' + LABELS[lang()].prev + '">‹</button>'
    + '<figure class="lb-figure"><img id="lbImg" alt=""><figcaption id="lbCap"></figcaption></figure>'
    + '<button class="lb-btn lb-next" aria-label="' + LABELS[lang()].next + '">›</button>'
    + '<div class="lb-counter" id="lbCounter"></div>';
  document.body.appendChild(box);
  var img = box.querySelector('#lbImg'), cap = box.querySelector('#lbCap'), counter = box.querySelector('#lbCounter');
  var cur = 0, touchX = null;
  function show(i){
    cur = (i + items.length) % items.length;
    img.setAttribute('src', items[cur].src);
    img.setAttribute('alt', items[cur].cap);
    cap.textContent = items[cur].cap;
    counter.textContent = (cur + 1) + ' / ' + items.length;
  }
  function open(i){ show(i); box.classList.add('open'); box.setAttribute('aria-hidden','false'); document.body.style.overflow = 'hidden'; }
  function close(){ box.classList.remove('open'); box.setAttribute('aria-hidden','true'); document.body.style.overflow = ''; }
  gallery.addEventListener('click', function(e){
    var btn = e.target.closest('.shot-btn'); if(!btn) return;
    var btns = Array.prototype.slice.call(gallery.querySelectorAll('.shot-btn'));
    open(btns.indexOf(btn));
  });
  box.querySelector('.lb-prev').addEventListener('click', function(){ show(cur - 1); });
  box.querySelector('.lb-next').addEventListener('click', function(){ show(cur + 1); });
  box.addEventListener('click', function(e){ if(e.target.closest('[data-lb-close]')) close(); });
  document.addEventListener('keydown', function(e){
    if(!box.classList.contains('open')) return;
    if(e.key === 'Escape') close();
    if(e.key === 'ArrowLeft') show(cur - 1);
    if(e.key === 'ArrowRight') show(cur + 1);
  });
  box.addEventListener('touchstart', function(e){ touchX = e.touches[0].clientX; }, {passive:true});
  box.addEventListener('touchend', function(e){
    if(touchX === null) return;
    var dx = e.changedTouches[0].clientX - touchX;
    if(Math.abs(dx) > 40) show(cur + (dx < 0 ? 1 : -1));
    touchX = null;
  }, {passive:true});
  window.addEventListener('langchange', function(){
    var L = lang();
    box.querySelector('.lb-close').setAttribute('aria-label', LABELS[L].close);
    box.querySelector('.lb-prev').setAttribute('aria-label', LABELS[L].prev);
    box.querySelector('.lb-next').setAttribute('aria-label', LABELS[L].next);
    collect();
    if(box.classList.contains('open')) show(cur);
  });
})();
