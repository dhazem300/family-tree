(function () {
  'use strict';

  const STYLE_ID = 'dual-calendar-style';

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = `
      .dual-date-widget{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;align-items:start;width:100%;}
      .dual-date-field{display:flex;flex-direction:column;gap:.35rem;min-width:0;}
      .dual-date-field span{font-size:.72rem;font-weight:900;color:#6b7280;letter-spacing:.02em;}
      html.dark .dual-date-field span{color:#E5B869;}
      .dual-date-input{width:100%;border-radius:.75rem;border:1px solid rgba(0,90,43,.12);background:rgba(255,255,255,.55);padding:.75rem 1rem;font-weight:700;font-size:.875rem;color:#111827;outline:none;min-height:48px;}
      html.dark .dual-date-input{border-color:rgba(229,184,105,.14);background:rgba(0,0,0,.20);color:#fff;}
      .dual-date-input:focus{box-shadow:0 0 0 3px rgba(0,90,43,.10);border-color:rgba(0,90,43,.35);}
      html.dark .dual-date-input:focus{box-shadow:0 0 0 3px rgba(229,184,105,.12);border-color:rgba(229,184,105,.45);}
      .dual-date-actions{grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap;margin-top:.1rem;}
      .dual-date-help{font-size:.72rem;font-weight:700;color:#6b7280;line-height:1.7;}
      html.dark .dual-date-help{color:#9ca3af;}
      .dual-date-clear{border:0;background:rgba(0,90,43,.08);color:#005A2B;border-radius:999px;padding:.35rem .8rem;font-size:.72rem;font-weight:900;cursor:pointer;}
      html.dark .dual-date-clear{background:rgba(229,184,105,.10);color:#E5B869;}
      .dual-date-message{grid-column:1/-1;font-size:.72rem;font-weight:900;line-height:1.7;margin-top:.15rem;display:none;}
      .dual-date-message.is-ok{display:block;color:#15803d;}
      .dual-date-message.is-error{display:block;color:#b91c1c;}
      html.dark .dual-date-message.is-ok{color:#86efac;}
      html.dark .dual-date-message.is-error{color:#fca5a5;}
      @media (max-width:640px){.dual-date-widget{grid-template-columns:1fr}.dual-date-actions{display:block}.dual-date-clear{margin-top:.5rem;width:100%;}}
    `;
    document.head.appendChild(style);
  }

  function pad(n) { return String(n).padStart(2, '0'); }

  function normalizeGregorian(value) {
    const m = String(value || '').trim().match(/^(\d{4})[-\/](\d{1,2})[-\/](\d{1,2})$/);
    if (!m) return '';
    const y = Number(m[1]);
    const mo = Number(m[2]);
    const d = Number(m[3]);
    if (!y || mo < 1 || mo > 12 || d < 1 || d > 31) return '';
    return `${y}-${pad(mo)}-${pad(d)}`;
  }

  function parseHijri(value) {
    const normalized = String(value || '')
      .trim()
      .replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d))
      .replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d));
    const m = normalized.match(/^(\d{3,4})[-\/](\d{1,2})[-\/](\d{1,2})$/);
    if (!m) return null;
    const y = Number(m[1]);
    const mo = Number(m[2]);
    const d = Number(m[3]);
    if (!y || mo < 1 || mo > 12 || d < 1 || d > 30) return null;
    return { y, m: mo, d };
  }

  const hijriFormatter = new Intl.DateTimeFormat('en-u-ca-islamic-umalqura', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });

  function gregorianToHijri(gregorian) {
    const normalized = normalizeGregorian(gregorian);
    if (!normalized) return '';
    const [y, m, d] = normalized.split('-').map(Number);
    const date = new Date(y, m - 1, d, 12, 0, 0);
    const parts = hijriFormatter.formatToParts(date);
    const part = name => Number((parts.find(p => p.type === name) || {}).value);
    const hy = part('year');
    const hm = part('month');
    const hd = part('day');
    if (!hy || !hm || !hd) return '';
    return `${hy}-${pad(hm)}-${pad(hd)}`;
  }

  function hijriPartsForGregorian(date) {
    const parts = hijriFormatter.formatToParts(date);
    const part = name => Number((parts.find(p => p.type === name) || {}).value);
    return { y: part('year'), m: part('month'), d: part('day') };
  }

  function hijriToGregorian(hijriValue) {
    const h = parseHijri(hijriValue);
    if (!h) return '';
    const estimatedYear = Math.floor(h.y * 0.970224 + 621.5774);
    const start = new Date(estimatedYear - 2, 0, 1, 12, 0, 0);
    const end = new Date(estimatedYear + 2, 11, 31, 12, 0, 0);

    for (let t = start.getTime(); t <= end.getTime(); t += 86400000) {
      const date = new Date(t);
      const p = hijriPartsForGregorian(date);
      if (p.y === h.y && p.m === h.m && p.d === h.d) {
        return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
      }
    }
    return '';
  }

  function showMessage(el, text, type) {
    if (!el) return;
    el.textContent = text;
    el.className = 'dual-date-message ' + (type === 'ok' ? 'is-ok' : 'is-error');
    if (type === 'ok') setTimeout(() => { el.className = 'dual-date-message'; }, 1800);
  }

  function setupField(source) {
    if (!source || source.dataset.dualDateReady === '1') return;
    source.dataset.dualDateReady = '1';

    const originalName = source.getAttribute('name') || '';
    const originalId = source.getAttribute('id') || '';
    const current = normalizeGregorian(source.value);
    const baseClass = source.className || 'field';

    source.type = 'hidden';
    source.value = current;
    source.className = '';

    const wrapper = document.createElement('div');
    wrapper.className = 'dual-date-widget';
    wrapper.setAttribute('data-dual-date-widget', originalName || originalId || 'date');

    const gregorianBox = document.createElement('label');
    gregorianBox.className = 'dual-date-field';
    gregorianBox.innerHTML = '<span>التاريخ الميلادي</span>';

    const gregorianInput = document.createElement('input');
    gregorianInput.type = 'date';
    gregorianInput.className = (baseClass.includes('field') ? 'field ' : '') + 'dual-date-input';
    gregorianInput.value = current;
    gregorianInput.autocomplete = 'off';
    if (originalId) gregorianInput.id = originalId + '_gregorian';
    gregorianBox.appendChild(gregorianInput);

    const hijriBox = document.createElement('label');
    hijriBox.className = 'dual-date-field';
    hijriBox.innerHTML = '<span>التاريخ الهجري</span>';

    const hijriInput = document.createElement('input');
    hijriInput.type = 'text';
    hijriInput.className = (baseClass.includes('field') ? 'field ' : '') + 'dual-date-input';
    hijriInput.placeholder = 'مثال: 1445-09-01';
    hijriInput.autocomplete = 'off';
    hijriInput.inputMode = 'numeric';
    hijriInput.value = current ? gregorianToHijri(current) : '';
    hijriBox.appendChild(hijriInput);

    const actions = document.createElement('div');
    actions.className = 'dual-date-actions';
    actions.innerHTML = '<span class="dual-date-help">يمكن اختيار التاريخ ميلاديًا أو كتابة التاريخ هجريًا بصيغة سنة-شهر-يوم.</span>';

    const clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'dual-date-clear';
    clearBtn.textContent = 'مسح التاريخ';
    actions.appendChild(clearBtn);

    const message = document.createElement('div');
    message.className = 'dual-date-message';

    wrapper.appendChild(gregorianBox);
    wrapper.appendChild(hijriBox);
    wrapper.appendChild(actions);
    wrapper.appendChild(message);
    source.insertAdjacentElement('afterend', wrapper);

    gregorianInput.addEventListener('change', () => {
      const g = normalizeGregorian(gregorianInput.value);
      source.value = g;
      hijriInput.value = g ? gregorianToHijri(g) : '';
      if (g) showMessage(message, 'تم تحديث التاريخ الهجري تلقائيًا.', 'ok');
    });

    hijriInput.addEventListener('blur', () => {
      const value = hijriInput.value.trim();
      if (!value) {
        source.value = '';
        gregorianInput.value = '';
        return;
      }
      const g = hijriToGregorian(value);
      if (!g) {
        showMessage(message, 'تعذر تحويل التاريخ الهجري. اكتب التاريخ بصيغة 1445-09-01.', 'error');
        return;
      }
      source.value = g;
      gregorianInput.value = g;
      hijriInput.value = gregorianToHijri(g);
      showMessage(message, 'تم تحويل التاريخ الهجري إلى ميلادي وحفظه.', 'ok');
    });

    hijriInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        hijriInput.blur();
      }
    });

    clearBtn.addEventListener('click', () => {
      source.value = '';
      gregorianInput.value = '';
      hijriInput.value = '';
      showMessage(message, 'تم مسح التاريخ.', 'ok');
    });
  }

  function init() {
    injectStyle();
    document.querySelectorAll('input[data-dual-date]').forEach(setupField);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
