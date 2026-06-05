(function(){
  function normalize(v){ return String(v || '').trim(); }
  const labels = {
    short_address: 'العنوان المختصر',
    building_no: 'رقم المبنى',
    street_ar: 'الشارع',
    street_en: 'Street',
    secondary_no: 'الرقم الفرعي',
    district_ar: 'الحي',
    district_en: 'District',
    postal_code: 'الرمز البريدي',
    city_ar: 'المدينة',
    city_en: 'City',
    country_ar: 'الدولة',
    country_en: 'Country'
  };
  function parseExisting(text){
    const out = {};
    const raw = normalize(text);
    if(!raw) return out;
    try{
      const obj = JSON.parse(raw);
      if(obj && typeof obj === 'object') return obj;
    }catch(e){}
    raw.split(/\n+/).forEach(line => {
      const parts = line.split(':');
      if(parts.length < 2) return;
      const keyLabel = normalize(parts.shift());
      const val = normalize(parts.join(':'));
      Object.keys(labels).forEach(k => {
        if(keyLabel === labels[k]) out[k] = val;
      });
    });
    return out;
  }
  function buildText(card){
    const lines = [];
    Object.keys(labels).forEach(key => {
      const input = card.querySelector(`[data-address-part="${key}"]`);
      const val = normalize(input && input.value);
      if(val) lines.push(`${labels[key]}: ${val}`);
    });
    return lines.join('\n');
  }
  function initCard(card){
    const hidden = card.querySelector('[data-address-hidden]');
    const preview = card.querySelector('[data-address-preview]');
    if(!hidden) return;
    const initial = hidden.value || hidden.textContent || '';
    const parsed = parseExisting(initial);
    let filled = false;
    Object.keys(parsed).forEach(key => {
      const input = card.querySelector(`[data-address-part="${key}"]`);
      if(input && parsed[key]) { input.value = parsed[key]; filled = true; }
    });
    function refresh(force){
      const txt = buildText(card);
      if(txt || force){
        hidden.value = txt;
        if(preview) preview.value = txt;
      } else if(initial){
        hidden.value = initial;
        if(preview) preview.value = initial;
      } else if(preview){
        preview.value = '';
      }
    }
    card.querySelectorAll('[data-address-part]').forEach(input => input.addEventListener('input', () => refresh(true)));
    refresh(filled);
  }
  document.addEventListener('DOMContentLoaded', () => document.querySelectorAll('[data-family-address-card]').forEach(initCard));
})();
