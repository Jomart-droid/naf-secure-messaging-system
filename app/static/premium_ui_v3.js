/* NAF Premium UI v3 - restrained command-grade interaction polish */
(function(){
  'use strict';
  const doc = document;
  doc.documentElement.classList.add('premium-ui-v3');

  function qs(sel, root){ return (root||doc).querySelector(sel); }
  function qsa(sel, root){ return Array.from((root||doc).querySelectorAll(sel)); }

  // Auto-highlight active navigation without relying on per-template classes.
  const path = location.pathname.replace(/\/$/,'') || '/';
  qsa('.nav-item').forEach(a=>{
    const href = (a.getAttribute('href') || '').replace(/\/$/,'') || '/';
    if(href && (path === href || (href !== '/' && path.startsWith(href + '/')))) a.classList.add('active');
  });

  // Composer workflow rail: real-time active/completed states.
  const form = qs('#broadcastForm');
  if(form){
    const steps = qsa('[data-composer-step]');
    const map = {
      routing: ['#targetScope','[name="from_unit_id"]','[name="branch_office"]','[name="action_unit_ids"]','[name="naf_all_units"]','[name="distribution_list_names"]','[name="channel_id"]'],
      precedence: ['[name="precedence_action"]','[name="precedence_info"]','[name="security_classification"]'],
      text: ['[name="title"]','[name="body"]'],
      submit: ['[name="attachments"]']
    };
    function hasValue(selector){
      const els = qsa(selector, form);
      return els.some(el=>{
        if(el.type === 'checkbox' || el.type === 'radio') return el.checked;
        if(el.type === 'file') return el.files && el.files.length > 0;
        return String(el.value || '').trim().length > 0;
      });
    }
    function stepComplete(key){
      if(key === 'routing'){
        const scope = qs('#targetScope', form);
        if(scope && scope.value === 'CHANNEL') return hasValue('[name="channel_id"]') && hasValue('[name="from_unit_id"]');
        return hasValue('[name="from_unit_id"]') && (hasValue('[name="action_unit_ids"]') || hasValue('[name="naf_all_units"]') || hasValue('[name="distribution_list_names"]'));
      }
      if(key === 'precedence') return true;
      if(key === 'text') return hasValue('[name="title"]') && hasValue('[name="body"]');
      if(key === 'submit') return hasValue('[name="attachments"]') || stepComplete('text');
      return false;
    }
    function focusStep(key){
      steps.forEach(s=>s.classList.toggle('active', s.dataset.composerStep === key));
    }
    function refreshSteps(){
      steps.forEach(s=>s.classList.toggle('complete', stepComplete(s.dataset.composerStep)));
      const body = qs('[name="body"]', form);
      const title = qs('[name="title"]', form);
      if(body && doc.activeElement === body) focusStep('text');
      else if(title && doc.activeElement === title) focusStep('text');
    }
    Object.entries(map).forEach(([key, selectors])=>{
      selectors.forEach(sel=>qsa(sel, form).forEach(el=>{
        ['focus','change','input'].forEach(evt=>el.addEventListener(evt, ()=>{ focusStep(key); refreshSteps(); }));
      }));
    });
    steps.forEach(btn=>btn.addEventListener('click', ()=>{
      const key = btn.dataset.composerStep;
      const target = key === 'routing' ? '#sectionRouting' : key === 'precedence' ? '#sectionPrecedence' : key === 'text' ? '#sectionText' : '#sectionSubmit';
      const el = qs(target);
      if(el) el.scrollIntoView({behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block:'start'});
      focusStep(key);
    }));
    form.addEventListener('input', refreshSteps);
    form.addEventListener('change', refreshSteps);
    refreshSteps();

    // Body word/character counter and clear quality feedback.
    const body = qs('#signal_body', form);
    if(body && !qs('.signal-text-meter')){
      const meter = doc.createElement('div');
      meter.className = 'signal-text-meter';
      meter.innerHTML = '<span>0 words</span><span>0 characters</span><span class="meter-status">Draft text pending</span>';
      body.insertAdjacentElement('afterend', meter);
      function updateMeter(){
        const raw = body.value || '';
        const words = raw.trim() ? raw.trim().split(/\s+/).length : 0;
        meter.children[0].textContent = words + ' words';
        meter.children[1].textContent = raw.length + ' characters';
        meter.children[2].textContent = words > 12 ? 'Text ready for preview' : 'Draft text pending';
        meter.classList.toggle('ready', words > 12);
      }
      body.addEventListener('input', updateMeter); updateMeter();
    }

    // Show selected attachment filenames as clean chips.
    const fileInput = qs('input[type="file"][name="attachments"]', form);
    if(fileInput && !qs('.selected-file-tray')){
      const tray = doc.createElement('div');
      tray.className = 'selected-file-tray';
      fileInput.insertAdjacentElement('afterend', tray);
      fileInput.addEventListener('change', ()=>{
        tray.innerHTML = '';
        Array.from(fileInput.files || []).slice(0,8).forEach(file=>{
          const chip = doc.createElement('span');
          chip.textContent = file.name;
          tray.appendChild(chip);
        });
        if((fileInput.files||[]).length > 8){ const more=doc.createElement('span'); more.textContent='+'+(fileInput.files.length-8)+' more'; tray.appendChild(more); }
      });
    }
  }

  // Make empty cards/pages feel deliberate, not unfinished.
  qsa('.world-empty').forEach(empty=>{
    if(!empty.querySelector('.empty-mark')){
      const mark = doc.createElement('span');
      mark.className = 'empty-mark';
      mark.textContent = '—';
      empty.prepend(mark);
    }
  });
})();
