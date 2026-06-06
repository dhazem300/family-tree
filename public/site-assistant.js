(function familySiteAssistant(){
  if (window.__familySiteAssistantLoaded) return;
  window.__familySiteAssistantLoaded = true;

  // المساعد الذكي - نسخة Premium محسنة: ظل واقعي + تحية احترافية + حجم مكبر في الشات
  const aiAvatarSvg = `
    <svg class="family-ai-saudi-svg" viewBox="0 0 170 180" aria-hidden="true" role="img" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id="saudiEyeGlow" x="-80%" y="-80%" width="260%" height="260%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="2.2" result="blur1"/>
          <feMerge>
            <feMergeNode in="blur1"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>

        <pattern id="shemaghPattern" width="12" height="12" patternUnits="userSpaceOnUse">
          <rect width="12" height="12" fill="#FFFFFF"/>
          <path d="M0 0 L12 12 M12 0 L0 12" stroke="#C62828" stroke-width="1.2" opacity="0.95"/>
          <path d="M6 0 L6 12 M0 6 L12 6" stroke="#D94A4A" stroke-width="0.6" opacity="0.45"/>
        </pattern>

        <linearGradient id="thoubPremium" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#FFFFFF"/>
          <stop offset="55%" stop-color="#F8FAFC"/>
          <stop offset="100%" stop-color="#E8EEF4"/>
        </linearGradient>

        <linearGradient id="metalPremium" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#F8FAFC"/>
          <stop offset="42%" stop-color="#CBD5E1"/>
          <stop offset="100%" stop-color="#64748B"/>
        </linearGradient>

        <linearGradient id="visorPremium" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#172033"/>
          <stop offset="48%" stop-color="#020617"/>
          <stop offset="100%" stop-color="#001F12"/>
        </linearGradient>
      </defs>

      <g class="saudi-avatar-group">

        <g class="robo-greeting-arm">
          <path class="robo-arm-sleeve-clean" d="M 116 119 C 128 112, 134 101, 136 89 C 137 83, 145 83, 146 90 C 147 105, 138 121, 123 132 C 120 128, 118 124, 116 119 Z"/>
          <path class="robo-arm-inner-clean" d="M 125 116 C 132 108, 136 99, 137 90" fill="none" stroke-width="2" stroke-linecap="round"/>
          <circle class="robo-clean-hand" cx="140" cy="87" r="7"/>
          <path class="robo-clean-hand-lines" d="M 136 83 L 132 78 M 140 80 L 140 74 M 144 83 L 149 78" fill="none" stroke-width="1.8" stroke-linecap="round"/>
        </g>

        <path class="robo-thoub" d="M 26 166 C 26 114, 48 103, 80 103 C 112 103, 134 114, 134 166 Z"/>
        <path class="robo-thoub-center" d="M 51 165 C 55 128, 65 113, 80 113 C 95 113, 105 128, 109 165 Z"/>
        <path class="robo-thoub-lines" d="M 52 116 L 52 166 M 108 116 L 108 166 M 80 104 L 80 124" stroke-width="2" fill="none" stroke-linecap="round"/>
        <path class="robo-thoub-collar" d="M 66 105 C 70 113, 76 117, 80 117 C 84 117, 90 113, 94 105" fill="none" stroke-width="2.4" stroke-linecap="round"/>

        <rect class="robo-neck" x="66" y="85" width="28" height="23" rx="5"/>
        <line class="robo-neck-line" x1="69" y1="92" x2="91" y2="92" stroke-width="2" stroke-linecap="round"/>
        <line class="robo-neck-line" x1="69" y1="99" x2="91" y2="99" stroke-width="2" stroke-linecap="round"/>

        <path class="robo-ghutra" d="M 38 61 C 38 20, 122 20, 122 61 L 136 126 C 138 139, 120 141, 112 128 L 106 62 L 54 62 L 48 128 C 40 141, 22 139, 24 126 Z"/>
        <path class="robo-ghutra-fold" d="M 54 66 C 52 83, 48 105, 43 126 M 106 66 C 108 83, 112 105, 117 126"/>
        <path class="robo-ghutra-side-shadow" d="M 43 72 C 40 91, 36 112, 32 127 C 35 132, 42 130, 47 123 L 53 64 Z"/>
        <path class="robo-ghutra-side-shadow right" d="M 117 72 C 120 91, 124 112, 128 127 C 125 132, 118 130, 113 123 L 107 64 Z"/>

        <rect class="robo-head" x="47" y="42" width="66" height="53" rx="20"/>
        <path class="robo-head-highlight" d="M 60 49 C 70 43, 88 44, 100 51" fill="none" stroke-width="2.3" stroke-linecap="round"/>

        <path class="robo-egal" d="M 43 49 C 62 60, 98 60, 117 49" fill="none" stroke-width="7" stroke-linecap="round"/>
        <path class="robo-egal" d="M 41 58 C 62 69, 98 69, 119 58" fill="none" stroke-width="7" stroke-linecap="round"/>

        <rect class="robo-visor" x="53" y="57" width="54" height="21" rx="9"/>
        <path class="robo-visor-glass" d="M 60 62 L 96 62" fill="none" stroke-width="2" stroke-linecap="round"/>

        <g class="robo-face-elements">
          <rect class="robo-eye robo-eye-left" x="61" y="64" width="12" height="5.5" rx="2.75" filter="url(#saudiEyeGlow)"/>
          <rect class="robo-eye robo-eye-right" x="87" y="64" width="12" height="5.5" rx="2.75" filter="url(#saudiEyeGlow)"/>
          <rect class="robo-scanner" x="56" y="72" width="8" height="2.2" rx="1.1" filter="url(#saudiEyeGlow)"/>
        </g>

        <circle class="robo-ear" cx="46" cy="68" r="4"/>
        <circle class="robo-ear" cx="114" cy="68" r="4"/>
        <circle class="robo-ear-dot" cx="46" cy="68" r="1.6"/>
        <circle class="robo-ear-dot" cx="114" cy="68" r="1.6"/>
      </g>
    </svg>`;

  const css = `
    .family-ai-button,
    .family-ai-panel,
    .family-ai-panel *,
    .family-ai-button * {
      box-sizing: border-box;
      font-family: Tajawal, Arial, sans-serif;
    }

    /* =========================
       الروبوت - الوضع الفاتح
    ========================= */
    .robo-thoub { fill: url(#thoubPremium); transition: .35s ease; }
    .robo-thoub-center { fill: rgba(0, 90, 43, 0.035); transition: .35s ease; }
    .robo-thoub-lines, .robo-thoub-collar { stroke: #D2DAE3; transition: .35s ease; }
    .robo-neck { fill: url(#metalPremium); transition: .35s ease; }
    .robo-neck-line { stroke: #475569; transition: .35s ease; }
    .robo-ghutra { fill: url(#shemaghPattern); transition: .35s ease; }
    .robo-ghutra-fold { fill: none; stroke: rgba(150, 45, 45, 0.42); stroke-width: 1.7; stroke-linecap: round; transition: .35s ease; }
    .robo-ghutra-side-shadow { fill: rgba(120, 20, 20, 0.05); transition: .35s ease; }
    .robo-head { fill: #E2E8F0; transition: .35s ease; }
    .robo-head-highlight { stroke: rgba(255,255,255,0.95); opacity: .95; transition: .35s ease; }
    .robo-egal { stroke: #101827; transition: .35s ease; }
    .robo-visor { fill: url(#visorPremium); transition: .35s ease; }
    .robo-visor-glass { stroke: rgba(255,255,255,0.20); transition: .35s ease; }
    .robo-eye { fill: #10B981; transition: fill .28s ease, transform .28s ease; will-change: transform, opacity; }
    .robo-scanner { fill: #34D399; opacity: .95; transition: fill .28s ease; will-change: transform; }
    .robo-ear { fill: #CBD5E1; transition: .35s ease; }
    .robo-ear-dot { fill: #005A2B; transition: .35s ease; }

    /* ذراع التحية */
    .robo-greeting-arm {
      opacity: 0;
      transform: translate(-10px, 18px) rotate(18deg) scale(.82);
      transform-origin: 118px 122px;
      transition: opacity .22s ease, transform .42s cubic-bezier(.16,1,.3,1);
      pointer-events: none;
      will-change: transform, opacity;
    }
    .robo-arm-sleeve-clean { fill: url(#thoubPremium); stroke: rgba(0,90,43,0.10); stroke-width: 1; }
    .robo-arm-inner-clean { stroke: #CBD5E1; }
    .robo-clean-hand { fill: url(#metalPremium); stroke: rgba(0,90,43,0.14); stroke-width: 1; }
    .robo-clean-hand-lines { stroke: #E5B869; opacity: .95; }

    /* =========================
       الوضع الداكن
    ========================= */
    html.dark .robo-thoub { fill: #F1F5F9; }
    html.dark .robo-thoub-center { fill: rgba(229,184,105,0.08); }
    html.dark .robo-thoub-lines, html.dark .robo-thoub-collar { stroke: #CBD5E1; }
    html.dark .robo-neck { fill: #64748B; }
    html.dark .robo-neck-line { stroke: #111827; }
    html.dark .robo-ghutra { fill: url(#shemaghPattern); }
    html.dark .robo-ghutra-fold { stroke: rgba(190,70,70,0.50); }
    html.dark .robo-ghutra-side-shadow { fill: rgba(2,6,23,0.10); }
    html.dark .robo-head { fill: #475569; }
    html.dark .robo-head-highlight { stroke: rgba(255,255,255,0.16); }
    html.dark .robo-egal { stroke: #020617; }
    html.dark .robo-visor { fill: #020617; }
    html.dark .robo-visor-glass { stroke: rgba(229,184,105,0.20); }
    html.dark .robo-eye { fill: #34D399; }
    html.dark .robo-scanner { fill: #6EE7B7; }
    html.dark .robo-ear { fill: #334155; }
    html.dark .robo-ear-dot { fill: #E5B869; }
    html.dark .robo-arm-sleeve-clean { fill: #F1F5F9; stroke: rgba(229,184,105,0.18); }
    html.dark .robo-arm-inner-clean { stroke: #CBD5E1; }
    html.dark .robo-clean-hand { fill: #64748B; stroke: rgba(229,184,105,0.22); }
    html.dark .robo-clean-hand-lines { stroke: #FBBF24; }

    /* =========================
       الحركات عالية الكفاءة
    ========================= */
    @keyframes roboBreathe {
      0%, 100% { transform: translateY(0) scale(1); }
      50% { transform: translateY(-4px) scale(1.01); }
    }
    @keyframes roboBlink {
      0%, 92%, 97%, 100% { transform: scaleY(1); opacity: 1; }
      95% { transform: scaleY(.12); opacity: .22; }
    }
    @keyframes roboScanner {
      0%, 100% { transform: translateX(0); }
      50% { transform: translateX(44px); }
    }
    @keyframes roboGreeting {
      0% { opacity: 0; transform: translateY(10px) scale(.94); }
      100% { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes cleanHandWave {
      0%, 100% { transform: translate(0, 0) rotate(-1deg) scale(1); }
      50% { transform: translate(1px, -3px) rotate(5deg) scale(1); }
    }
    @keyframes panelSlidePremium {
      0% { opacity: 0; transform: translateY(28px) scale(.96); filter: blur(7px); }
      100% { opacity: 1; transform: translateY(0) scale(1); filter: blur(0); }
    }
    @keyframes msgPopPremium {
      from { opacity: 0; transform: translateY(10px) scale(.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes premiumShimmer {
      0% { transform: translateX(140%) rotate(18deg); }
      100% { transform: translateX(-160%) rotate(18deg); }
    }

    .saudi-avatar-group {
      transform-origin: center;
      animation: roboBreathe 4.8s ease-in-out infinite;
      will-change: transform;
    }
    .robo-eye {
      transform-origin: center;
      animation: roboBlink 4.4s infinite;
    }
    .robo-scanner {
      animation: roboScanner 3s ease-in-out infinite;
    }

    /* =========================
       زر الروبوت العائم
    ========================= */
    .family-ai-button {
      position: fixed; left: 18px; bottom: 12px; z-index: 99990; width: 92px; height: 112px; border: 0; background: transparent; box-shadow: none; outline: none; display: flex; align-items: flex-end; justify-content: center; cursor: pointer; padding: 0; overflow: visible; transition: transform .28s ease; -webkit-tap-highlight-color: transparent;
    }
    .family-ai-button::before {
      content: ''; position: absolute; left: 50%; bottom: 10px; width: 76px; height: 106px; transform: translateX(-50%) scale(.96);
      background: radial-gradient(ellipse at center, rgba(15,23,42,0.18) 0%, rgba(15,23,42,0.10) 38%, rgba(15,23,42,0.035) 58%, rgba(15,23,42,0) 76%);
      filter: blur(10px); z-index: 0; pointer-events: none; opacity: .78; transition: transform .32s ease, opacity .32s ease; will-change: transform, opacity;
    }
    .family-ai-button::after {
      content: ''; position: absolute; left: 50%; bottom: 3px; width: 62px; height: 13px; transform: translateX(-50%);
      background: radial-gradient(ellipse at center, rgba(15,23,42,0.24) 0%, rgba(15,23,42,0.12) 42%, rgba(15,23,42,0) 74%);
      filter: blur(4px); z-index: 0; pointer-events: none; opacity: .72; transition: transform .32s ease, opacity .32s ease; will-change: transform, opacity;
    }
    html.dark .family-ai-button::before {
      background: radial-gradient(ellipse at center, rgba(0,0,0,0.56) 0%, rgba(0,0,0,0.32) 38%, rgba(229,184,105,0.055) 58%, rgba(0,0,0,0) 78%);
      filter: blur(12px); opacity: .92;
    }
    html.dark .family-ai-button::after {
      background: radial-gradient(ellipse at center, rgba(0,0,0,0.60) 0%, rgba(0,0,0,0.32) 45%, rgba(0,0,0,0) 76%);
      filter: blur(5px); opacity: .9;
    }
    .family-ai-button:hover { transform: translateY(-5px); }
    .family-ai-button:focus-visible { outline: 3px solid rgba(229,184,105,.55); outline-offset: 4px; border-radius: 24px; }

    .family-ai-saudi-svg {
      width: 100%; height: 100%; display: block; overflow: visible; filter: none !important; transition: transform .32s cubic-bezier(.16,1,.3,1); will-change: transform; position: relative; z-index: 2;
    }
    .family-ai-button:hover .family-ai-saudi-svg { transform: scale(1.18) rotate(-1deg); filter: none !important; }
    .family-ai-button:hover::before { transform: translateX(-50%) scale(1.18); opacity: .95; }
    .family-ai-button:hover::after { transform: translateX(-50%) scale(1.16); opacity: .9; }

    .family-ai-button:hover .robo-greeting-arm, .family-ai-button:focus-visible .robo-greeting-arm {
      opacity: 1; transform: translate(0, 0) rotate(0deg) scale(1); animation: cleanHandWave .95s ease-in-out infinite;
    }
    .family-ai-button:hover .robo-eye { fill: #E5B869; transform: scaleX(1.18); }
    html.dark .family-ai-button:hover .robo-eye { fill: #FBBF24; }
    .family-ai-button:hover .robo-scanner { fill: #E5B869; animation-duration: .9s; }
    .family-ai-button:hover .saudi-avatar-group { animation-duration: 2.4s; }

    /* رسالة الترحيب */
    .family-ai-hover-tip {
      position: absolute; bottom: 102px; left: 48px; min-width: 94px; text-align: center; background: linear-gradient(135deg, #005A2B, #003D1D); color: #FFFFFF; padding: 10px 15px; border-radius: 18px 18px 18px 6px; font-size: 13px; font-weight: 900; line-height: 1; white-space: nowrap; border: 1px solid rgba(229,184,105,0.42); box-shadow: 0 10px 22px rgba(0,0,0,0.12), inset 0 1px 0 rgba(255,255,255,0.10); opacity: 0; pointer-events: none; transform-origin: bottom center; z-index: 3; will-change: transform, opacity;
    }
    .family-ai-hover-tip::after {
      content: ''; position: absolute; bottom: -6px; left: 20px; width: 12px; height: 12px; background: #004521; transform: rotate(45deg); border-right: 1px solid rgba(229,184,105,0.28); border-bottom: 1px solid rgba(229,184,105,0.28);
    }
    .family-ai-hover-tip::before {
      content: ''; position: absolute; top: 4px; right: 8px; width: 26px; height: 1px; background: rgba(229,184,105,0.55); border-radius: 999px;
    }
    .family-ai-button:hover .family-ai-hover-tip, .family-ai-button:focus-visible .family-ai-hover-tip {
      opacity: 1; animation: roboGreeting .22s ease forwards;
    }
    html.dark .family-ai-hover-tip { background: linear-gradient(135deg, #111827, #020617); color: #E5B869; border-color: rgba(229,184,105,0.40); box-shadow: 0 12px 26px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.06); }
    html.dark .family-ai-hover-tip::after { background: #050816; }

    /* =========================
       لوحة الشات
    ========================= */
    .family-ai-panel {
      position: fixed; left: 24px; bottom: 124px; z-index: 99991; width: min(450px, calc(100vw - 48px)); height: min(680px, calc(100vh - 165px)); border-radius: 32px; overflow: hidden; display: none; direction: rtl; color: #111827; background: linear-gradient(180deg, rgba(255,255,255,0.97), rgba(248,250,252,0.94)); border: 1px solid rgba(0,90,43,0.12); box-shadow: 0 34px 90px rgba(15,23,42,0.16), 0 12px 34px rgba(0,90,43,0.08); backdrop-filter: blur(22px); -webkit-backdrop-filter: blur(22px); transform-origin: bottom left; will-change: transform, opacity;
    }
    .family-ai-panel::before {
      content: ''; position: absolute; inset: 0; pointer-events: none; background: radial-gradient(circle at top right, rgba(229,184,105,0.13), transparent 35%), radial-gradient(circle at bottom left, rgba(0,90,43,0.09), transparent 34%); z-index: 0;
    }
    .family-ai-panel > * { position: relative; z-index: 1; }
    html.dark .family-ai-panel { color: #F8FAFC; background: linear-gradient(180deg, rgba(10,14,22,0.97), rgba(2,6,23,0.95)); border-color: rgba(229,184,105,0.18); box-shadow: 0 34px 96px rgba(0,0,0,0.68), 0 0 28px rgba(229,184,105,0.04); }
    .family-ai-panel.open { display: flex; flex-direction: column; animation: panelSlidePremium .42s cubic-bezier(.16,1,.3,1) forwards; }

    /* تكبير وتعديل الترويسة ومجسم الروبوت داخل الشات */
    .family-ai-head {
      padding: 18px 24px; color: #fff; display: flex; align-items: center; gap: 18px; border-bottom: 2px solid #E5B869; position: relative; overflow: hidden; background: linear-gradient(135deg, #005A2B 0%, #003D1D 60%, #002B14 100%); min-height: 125px; /* زيادة ارتفاع الترويسة */
    }
    .family-ai-head::before {
      content: ''; position: absolute; inset: 0; opacity: .13; pointer-events: none; background-image: linear-gradient(45deg, rgba(229,184,105,0.55) 1px, transparent 1px), linear-gradient(-45deg, rgba(229,184,105,0.35) 1px, transparent 1px); background-size: 22px 22px;
    }
    .family-ai-head::after {
      content: ''; position: absolute; width: 44px; height: 160%; top: -30%; right: -70px; background: linear-gradient(90deg, transparent, rgba(255,255,255,.22), transparent); animation: premiumShimmer 5.8s ease-in-out infinite; pointer-events: none;
    }
    html.dark .family-ai-head { background: linear-gradient(135deg, #111827 0%, #020617 62%, #000000 100%); }

    /* تم تكبير الروبوت بقوة ليتناسب مع المحيط الجديد */
    .family-ai-head-icon {
      width: 90px; height: 90px; display: grid; place-items: center; flex: 0 0 auto; background: transparent; border: 0; box-shadow: none; overflow: visible; margin-left: 4px;
    }
    .family-ai-head-icon .family-ai-saudi-svg {
      width: 90px; height: 90px; filter: none !important; transform: scale(1.15) translateY(4px); /* إعطائه تأثير الخروج من الإطار قليلا */
    }

    .family-ai-title { font-weight: 900; font-size: 21px; line-height: 1.1; color: #E5B869; letter-spacing: -.2px; text-shadow: 0 2px 12px rgba(0,0,0,.18); }
    .family-ai-sub { font-size: 11.6px; opacity: .94; margin-top: 6px; font-weight: 600; line-height: 1.55; color: #E5E7EB; max-width: 285px; }
    .family-ai-close { margin-right: auto; background: rgba(255,255,255,0.10); border: 1px solid rgba(255,255,255,0.12); color: #fff; width: 38px; height: 38px; border-radius: 50%; cursor: pointer; font-size: 23px; display: grid; place-items: center; transition: .25s ease; z-index: 2; line-height: 1; flex: 0 0 auto; }
    .family-ai-close:hover { background: #E5B869; color: #003D1D; transform: rotate(90deg) scale(1.05); box-shadow: 0 8px 18px rgba(229,184,105,.25); }

    .family-ai-messages { flex: 1; overflow-y: auto; padding: 22px 20px; scroll-behavior: smooth; background: linear-gradient(180deg, rgba(0,90,43,0.035), rgba(229,184,105,0.045)); }
    html.dark .family-ai-messages { background: linear-gradient(180deg, rgba(255,255,255,0.012), rgba(229,184,105,0.035)); }
    .family-ai-messages::-webkit-scrollbar { width: 7px; } .family-ai-messages::-webkit-scrollbar-track { background: transparent; } .family-ai-messages::-webkit-scrollbar-thumb { background: linear-gradient(180deg, #E5B869, #005A2B); border-radius: 999px; }

    .family-ai-msg { max-width: 86%; padding: 14px 18px; border-radius: 22px; margin-bottom: 13px; line-height: 1.78; font-size: 14px; font-weight: 700; white-space: pre-wrap; animation: msgPopPremium .28s ease forwards; box-shadow: 0 8px 20px rgba(15,23,42,0.06), inset 0 1px 0 rgba(255,255,255,0.36); position: relative; will-change: transform, opacity; }
    .family-ai-msg.bot { background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(248,250,252,0.94)); color: #003D1D; border-top-right-radius: 7px; border: 1px solid rgba(0,90,43,0.08); border-right: 4px solid #E5B869; }
    .family-ai-msg.user { background: linear-gradient(135deg, #005A2B, #003D1D); color: #fff; margin-right: auto; border-top-left-radius: 7px; border-left: 4px solid #E5B869; box-shadow: 0 10px 24px rgba(0,90,43,0.22), inset 0 1px 0 rgba(255,255,255,0.12); }
    html.dark .family-ai-msg.bot { background: linear-gradient(180deg, rgba(30,41,59,0.88), rgba(15,23,42,0.84)); color: #F8FAFC; border-color: rgba(229,184,105,0.15); border-right-color: #E5B869; box-shadow: 0 10px 24px rgba(0,0,0,0.24), inset 0 1px 0 rgba(255,255,255,0.055); }
    html.dark .family-ai-msg.user { background: linear-gradient(135deg, #E5B869, #C9973E); color: #050505; border-left-color: #005A2B; }

    .family-ai-mode { display: inline-flex; align-items: center; gap: 7px; margin: 3px 0 14px; padding: 7px 13px; border-radius: 999px; background: linear-gradient(135deg, rgba(229,184,105,0.16), rgba(0,90,43,0.06)); color: #005A2B; font-size: 11px; font-weight: 900; border: 1px solid rgba(229,184,105,0.30); box-shadow: 0 5px 14px rgba(0,0,0,0.04); }
    .family-ai-mode::before { content: ''; width: 7px; height: 7px; border-radius: 50%; background: #10B981; box-shadow: 0 0 0 4px rgba(16,185,129,0.12); }
    html.dark .family-ai-mode { color: #E5B869; background: rgba(229,184,105,0.09); border-color: rgba(229,184,105,0.20); }

    .family-ai-actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 14px; }
    .family-ai-action { display: inline-flex; align-items: center; justify-content: center; gap: 7px; text-decoration: none; padding: 10px 16px; border-radius: 15px; background: linear-gradient(135deg, #005A2B, #003D1D); color: #fff; font-size: 12px; font-weight: 900; box-shadow: 0 6px 16px rgba(0,90,43,0.20); transition: .25s ease; border: 1px solid rgba(0,90,43,0.28); }
    .family-ai-action::before { content: '↗'; font-size: 12px; opacity: .92; }
    .family-ai-action:hover { background: linear-gradient(135deg, #F4D48A, #E5B869); color: #003D1D; transform: translateY(-2px); border-color: #E5B869; box-shadow: 0 8px 20px rgba(229,184,105,.25); }
    html.dark .family-ai-action { background: linear-gradient(135deg, #E5B869, #C9973E); color: #050505; border-color: rgba(229,184,105,.40); }
    html.dark .family-ai-action:hover { background: #fff; color: #111827; }

    .family-ai-suggestions { display: flex; flex-wrap: wrap; gap: 8px; padding: 0 20px 16px; background: transparent; transition: .25s ease; }
    .family-ai-suggestions button { border: 1px solid rgba(0,90,43,0.14); background: linear-gradient(180deg, rgba(255,255,255,0.92), rgba(248,250,252,0.82)); color: #005A2B; padding: 8px 14px; border-radius: 999px; font-size: 12px; font-weight: 800; cursor: pointer; transition: .25s ease; box-shadow: 0 4px 12px rgba(15,23,42,0.045); backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px); }
    .family-ai-suggestions button:hover { background: linear-gradient(135deg, #005A2B, #003D1D); color: #fff; border-color: #005A2B; transform: translateY(-2px); box-shadow: 0 8px 18px rgba(0,90,43,0.15); }
    html.dark .family-ai-suggestions button { background: rgba(255,255,255,0.045); border-color: rgba(229,184,105,0.22); color: #E5B869; box-shadow: none; }
    html.dark .family-ai-suggestions button:hover { background: #E5B869; color: #050505; }

    .family-ai-form { display: flex; gap: 10px; padding: 16px 20px 18px; border-top: 1px solid rgba(0,90,43,0.08); background: linear-gradient(180deg, rgba(255,255,255,0.76), rgba(255,255,255,0.92)); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); }
    html.dark .family-ai-form { background: linear-gradient(180deg, rgba(5,5,5,0.46), rgba(2,6,23,0.72)); border-top-color: rgba(229,184,105,0.12); }
    .family-ai-input { flex: 1; min-width: 0; border: 1px solid rgba(0,90,43,0.16); background: rgba(255,255,255,0.95); border-radius: 18px; padding: 14px 16px; outline: none; font-weight: 700; color: #111827; transition: all .25s ease; box-shadow: inset 0 1px 0 rgba(255,255,255,.9); }
    .family-ai-input::placeholder { color: rgba(17,24,39,0.48); }
    .family-ai-input:focus { border-color: #E5B869; box-shadow: 0 0 0 4px rgba(229,184,105,0.13), inset 0 1px 0 rgba(255,255,255,.9); background: #fff; }
    html.dark .family-ai-input { background: rgba(255,255,255,0.055); border-color: rgba(255,255,255,0.10); color: #fff; box-shadow: inset 0 1px 0 rgba(255,255,255,0.04); }
    html.dark .family-ai-input::placeholder { color: rgba(255,255,255,0.45); }
    html.dark .family-ai-input:focus { border-color: #E5B869; box-shadow: 0 0 0 4px rgba(229,184,105,0.18); background: rgba(255,255,255,0.075); }
    .family-ai-send { border: 0; background: linear-gradient(135deg, #F4D48A, #E5B869 52%, #C9973E); color: #003D1D; border-radius: 17px; padding: 0 22px; font-weight: 900; cursor: pointer; transition: .25s ease; box-shadow: 0 6px 16px rgba(229,184,105,0.32), inset 0 1px 0 rgba(255,255,255,0.32); white-space: nowrap; }
    .family-ai-send:hover { transform: translateY(-2px) scale(1.02); box-shadow: 0 10px 22px rgba(229,184,105,0.40), inset 0 1px 0 rgba(255,255,255,0.38); filter: saturate(1.06); }
    .family-ai-send:active { transform: translateY(0) scale(.99); }
    html.dark .family-ai-send { color: #050505; }

    @media(max-width:640px){
      .family-ai-button { left: 10px; bottom: 6px; width: 78px; height: 96px; }
      .family-ai-button::before { width: 66px; height: 90px; }
      .family-ai-button::after { width: 56px; }
      .family-ai-hover-tip { bottom: 88px; left: 38px; font-size: 12px; padding: 9px 13px; border-radius: 16px 16px 16px 6px; }
      .family-ai-panel { left: 12px; right: 12px; bottom: 102px; width: auto; height: min(590px, calc(100vh - 130px)); border-radius: 26px; }
      
      .family-ai-head { padding: 16px; gap: 14px; min-height: 105px; }
      .family-ai-head-icon { width: 74px; height: 74px; }
      .family-ai-head-icon .family-ai-saudi-svg { width: 74px; height: 74px; }
      .family-ai-title { font-size: 19px; }
      .family-ai-sub { font-size: 10.8px; max-width: 220px; }
      
      .family-ai-messages { padding: 18px 16px; }
      .family-ai-msg { max-width: 92%; font-size: 13.5px; }
      .family-ai-form { padding: 12px 14px 14px; gap: 8px; }
      .family-ai-input { padding: 13px 14px; border-radius: 16px; }
      .family-ai-send { padding: 0 17px; border-radius: 15px; }
      .family-ai-suggestions { padding: 0 16px 12px; }
    }

    @media(max-width:390px){
      .family-ai-button { width: 72px; height: 90px; }
      .family-ai-hover-tip { bottom: 82px; left: 35px; }
      .family-ai-panel { bottom: 98px; height: min(560px, calc(100vh - 120px)); }
      .family-ai-head { min-height: 95px; }
      .family-ai-head-icon { width: 68px; height: 68px; }
      .family-ai-head-icon .family-ai-saudi-svg { width: 68px; height: 68px; }
      .family-ai-sub { display: none; }
      .family-ai-send { padding: 0 14px; }
    }

    @media (prefers-reduced-motion: reduce) {
      .family-ai-button, .family-ai-button *, .family-ai-panel, .family-ai-panel *, .saudi-avatar-group, .robo-eye, .robo-scanner, .robo-greeting-arm {
        animation: none !important; transition: none !important;
      }
    }
  `;

  const style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);

  const button = document.createElement('button');
  button.className = 'family-ai-button';
  button.type = 'button';
  button.setAttribute('aria-label','مساعد الموقع الذكي');
  button.innerHTML = `${aiAvatarSvg}<span class="family-ai-hover-tip">هلا اتفضل</span>`;

  const panel = document.createElement('section');
  panel.className = 'family-ai-panel';
  panel.innerHTML = `
    <div class="family-ai-head">
      <div class="family-ai-head-icon">${aiAvatarSvg}</div>
      <div><div class="family-ai-title">المساعد الذكي</div><div class="family-ai-sub">اسأل عن آلية الموقع، إدارة الموقع، طريقة التواصل، الأفراد، صلة القرابة، أو أي سؤال عام.</div></div>
      <button class="family-ai-close" type="button" aria-label="إغلاق">×</button>
    </div>
    <div class="family-ai-messages" id="familyAiMessages"></div>
    <div class="family-ai-suggestions">
      <button type="button">احكيلي تاريخ العائلة</button>
      <button type="button">آلية عمل الموقع</button>
      <button type="button">من يدير الموقع؟</button>
      <button type="button">كيف نتواصل مع إدارة الموقع؟</button>
      <button type="button">ما صلة القرابة؟</button>
    </div>
    <form class="family-ai-form" id="familyAiForm">
      <input class="family-ai-input" id="familyAiInput" placeholder="اسأل المساعد الذكي عن أي معلومة..." autocomplete="off">
      <button class="family-ai-send" type="submit">إرسال</button>
    </form>`;

  document.body.appendChild(button);
  document.body.appendChild(panel);

  const messages = panel.querySelector('#familyAiMessages');
  const input = panel.querySelector('#familyAiInput');
  const form = panel.querySelector('#familyAiForm');
  const closeBtn = panel.querySelector('.family-ai-close');
  const suggestionsBox = panel.querySelector('.family-ai-suggestions');
  const suggestions = panel.querySelectorAll('.family-ai-suggestions button');

  function addMsg(text, who){
    const div = document.createElement('div');
    div.className = 'family-ai-msg ' + (who || 'bot');
    div.textContent = text;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
  }

  function addMode(mode){
    if (!mode) return;
    const div = document.createElement('div');
    div.className = 'family-ai-mode';
    div.textContent = mode === 'site' ? 'إجابة من بيانات الموقع' : 'إجابة عامة بالذكاء الاصطناعي';
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
  }

  function addActions(actions){
    if (!Array.isArray(actions) || !actions.length) return;
    const wrap = document.createElement('div');
    wrap.className = 'family-ai-actions';
    actions.forEach((action) => {
      if (!action || !action.url || !action.label) return;
      const a = document.createElement('a');
      a.href = action.url;
      a.className = 'family-ai-action';
      a.textContent = action.label;
      wrap.appendChild(a);
    });
    if (wrap.childElementCount) {
      messages.appendChild(wrap);
      messages.scrollTop = messages.scrollHeight;
    }
  }

  function openPanel(){
    panel.classList.add('open');
    if (!messages.childElementCount) addMsg('مرحباً بك، أنا المساعد الذكي للموقع. كيف أستطيع مساعدتك اليوم؟');
    setTimeout(()=>input.focus(), 80);
  }

  function closePanel(){
    panel.classList.remove('open');
  }

  button.addEventListener('click', () => panel.classList.contains('open') ? closePanel() : openPanel());
  closeBtn.addEventListener('click', closePanel);

  async function ask(question){
    const q = (question || '').trim();
    if (!q) return;
    addMsg(q, 'user');
    if (suggestionsBox) suggestionsBox.style.display = 'none';
    input.value = '';
    const thinking = document.createElement('div');
    thinking.className = 'family-ai-msg bot';
    thinking.textContent = 'جاري المعالجة والبحث داخل بيانات الشجرة...';
    messages.appendChild(thinking);
    messages.scrollTop = messages.scrollHeight;

    try {
      const res = await fetch('/api/site-assistant', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({question:q})
      });

      const data = await res.json();
      thinking.remove();
      addMsg(data.answer || 'لم أفهم السؤال بشكل كافٍ. اكتب اسم الشخص ثلاثي أو رباعي أو وضّح المطلوب.', 'bot');
      addMode(data.mode);

      if (Array.isArray(data.actions) && data.actions.length) {
        addActions(data.actions);
      } else if (data.link) {
        addActions([{ label: data.linkLabel || 'فتح الرابط', url: data.link }]);
      }
    } catch(e) {
      thinking.remove();
      addMsg('حدث خطأ أثناء الاتصال بالأنظمة. يرجى المحاولة مرة أخرى.', 'bot');
    }
  }

  form.addEventListener('submit', (e)=>{
    e.preventDefault();
    ask(input.value);
  });

  suggestions.forEach(b=>b.addEventListener('click', ()=>{
    openPanel();
    ask(b.textContent || '');
  }));
})();