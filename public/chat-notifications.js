(function(){
  if (window.__familyNotifyLoaded) return;
  window.__familyNotifyLoaded = true;
  function ensureBadge(link, cls){
    if(!link || link.querySelector('.'+cls)) return null;
    if(getComputedStyle(link).position === 'static') link.style.position = 'relative';
    const badge = document.createElement('span');
    badge.className = cls;
    badge.style.cssText = 'position:absolute;top:-6px;left:-6px;min-width:20px;height:20px;padding:0 5px;border-radius:999px;background:#dc2626;color:#fff;font-size:11px;font-weight:900;line-height:20px;text-align:center;box-shadow:0 6px 16px rgba(0,0,0,.22);z-index:10;display:none';
    link.appendChild(badge);
    return badge;
  }
  function updateBadges(selector, cls, count){
    document.querySelectorAll(selector).forEach(link => {
      const badge = ensureBadge(link, cls) || link.querySelector('.'+cls);
      if(!badge) return;
      badge.textContent = count > 99 ? '99+' : String(count);
      badge.style.display = count > 0 ? 'inline-block' : 'none';
    });
  }
  function toast(text, href, key){
    if(!text || sessionStorage.getItem(key) === text) return;
    sessionStorage.setItem(key, text);
    const el = document.createElement('a');
    el.href = href;
    el.textContent = text;
    el.style.cssText = 'position:fixed;bottom:22px;left:22px;z-index:9999;background:#005A2B;color:#fff;padding:14px 18px;border-radius:18px;font-family:Tajawal,Arial,sans-serif;font-weight:900;box-shadow:0 16px 38px rgba(0,0,0,.24);text-decoration:none';
    document.body.appendChild(el);
    setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateY(8px)'; el.style.transition='all .35s ease'; setTimeout(()=>el.remove(), 400); }, 6500);
  }
  async function refresh(){
    try{
      const chat = await fetch('/api/chat/unread-count', {cache:'no-store'}).then(r=>r.json()).catch(()=>({ok:false}));
      if(chat.ok){
        const n = Number(chat.unread||0);
        updateBadges('a[href="/chat"]', 'family-chat-unread-badge', n);
        if(n && !location.pathname.startsWith('/chat')) toast(`لديك ${n} رسالة جديدة`, '/chat', 'chat-toast-'+n);
      }
      const notifications = await fetch('/api/notifications/unread', {cache:'no-store'}).then(r=>r.json()).catch(()=>({ok:false}));
      if(notifications.ok){
        const n = Number(notifications.unread||0);
        updateBadges('a[href="/notifications"]', 'family-notify-unread-badge', n);
        if(n && location.pathname !== '/notifications') toast(`لديك ${n} إشعار جديد`, '/notifications', 'notify-toast-'+n);
      }
    }catch(e){}
  }
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', refresh); else refresh();
  setInterval(refresh, 30000);
})();
