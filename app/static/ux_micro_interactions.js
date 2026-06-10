/* NAF SSS - Recommendation 11 & 21 deep implementation
   Professional loading states + restrained mission-grade micro-interactions.
   Works with existing Flask/Jinja screens without requiring per-page rewrites. */
(function(){
  'use strict';

  const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const doc = document.documentElement;
  const body = document.body;
  const loader = document.getElementById('appLoader');
  const loaderText = loader ? loader.querySelector('.loader-text') : null;
  const loaderSub = loader ? loader.querySelector('.loader-sub') : null;
  const toastStack = document.getElementById('liveToastStack');

  function setBusy(isBusy, message, subMessage){
    if(!loader) return;
    if(message && loaderText) loaderText.textContent = message;
    if(subMessage && loaderSub) loaderSub.textContent = subMessage;
    loader.classList.toggle('show', !!isBusy);
    loader.setAttribute('aria-hidden', isBusy ? 'false' : 'true');
    doc.classList.toggle('is-busy', !!isBusy);
  }

  function inferMessage(text, href){
    const s = ((text || '') + ' ' + (href || '')).toLowerCase();
    if(s.includes('pdf') || s.includes('print')) return ['Preparing secure document…','Applying watermark, signature, and access controls'];
    if(s.includes('download') || s.includes('export') || s.includes('backup')) return ['Preparing protected export…','Packaging records with audit controls'];
    if(s.includes('release') || s.includes('sign')) return ['Signing and releasing signal…','Verifying authority and recording audit trail'];
    if(s.includes('send') || s.includes('submit')) return ['Submitting request…','Validating workflow and notifying recipients'];
    if(s.includes('delete') || s.includes('remove')) return ['Applying change…','Updating records and audit trail'];
    if(s.includes('search') || s.includes('filter')) return ['Searching records…','Checking available signal indexes'];
    return ['Processing…','Session active • Audit logging enabled'];
  }

  window.NAFUX = window.NAFUX || {};
  window.NAFUX.setBusy = setBusy;
  window.NAFUX.showProgress = function(message, subMessage){ setBusy(true, message || 'Processing…', subMessage || 'Session active • Audit logging enabled'); };
  window.NAFUX.hideProgress = function(){ setBusy(false); };

  // Hide the initial loader after content is ready, but leave it available for actions.
  window.addEventListener('load', function(){
    window.setTimeout(function(){ setBusy(false); }, 180);
    body.classList.add('page-ready');
  });

  // Professional toast system: replaces harsh alerts where pages call showToast.
  window.showToast = window.showToast || function(title, message, href, type){
    if(!toastStack) return;
    const toast = document.createElement('div');
    toast.className = 'premium-toast ' + (type || 'info');
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
    toast.innerHTML = '<div class="toast-mark" aria-hidden="true"></div><div class="toast-copy"><strong></strong><p></p></div><button type="button" class="toast-close" aria-label="Dismiss notification">×</button>';
    toast.querySelector('strong').textContent = title || 'Notice';
    toast.querySelector('p').textContent = message || '';
    if(href){
      toast.addEventListener('click', function(e){ if(!e.target.closest('button')) window.location.href = href; });
      toast.classList.add('clickable');
    }
    toast.querySelector('button').addEventListener('click', function(){ dismiss(toast); });
    toastStack.appendChild(toast);
    requestAnimationFrame(function(){ toast.classList.add('show'); });
    window.setTimeout(function(){ dismiss(toast); }, type === 'error' ? 7200 : 5200);
    function dismiss(node){
      node.classList.remove('show');
      window.setTimeout(function(){ if(node.parentNode) node.parentNode.removeChild(node); }, 220);
    }
  };

  // Button ripples, press feedback, and accessible loading labels.
  document.addEventListener('pointerdown', function(e){
    const btn = e.target.closest('button,.btn,.btn-primary,a.nav-item,a.card,a.world-message-row');
    if(!btn || prefersReduced) return;
    if(btn.classList.contains('no-ripple')) return;
    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement('span');
    ripple.className = 'ux-ripple';
    const size = Math.max(rect.width, rect.height);
    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = (e.clientX - rect.left - size/2) + 'px';
    ripple.style.top = (e.clientY - rect.top - size/2) + 'px';
    btn.appendChild(ripple);
    window.setTimeout(function(){ if(ripple.parentNode) ripple.parentNode.removeChild(ripple); }, 620);
  });

  // The full-screen processing overlay must only appear for explicit signal-processing actions.
  // Ordinary navigation, downloads, Signal Bank browsing, and direct messages use normal button feedback only.
  document.addEventListener('click', function(e){
    const a = e.target.closest('a[href]');
    if(!a) return;
    if(a.target === '_blank' || a.hasAttribute('download') || a.dataset.noLoader === 'true') return;
    if(a.dataset.signalProcessing !== 'true' && !a.hasAttribute('data-signal-processing')) return;
    const href = a.getAttribute('href') || '';
    if(!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) return;
    const [msg, sub] = inferMessage(a.textContent, href);
    window.setTimeout(function(){ setBusy(true, msg, sub); }, 80);
  }, true);

  // Form submit: prevent accidental duplicates. The full-screen processing overlay is only for official signal send/release flows.
  document.addEventListener('submit', function(e){
    const form = e.target;
    if(!(form instanceof HTMLFormElement)) return;
    if(form.dataset.noLoader === 'true' || form.hasAttribute('data-no-loader') || form.dataset.noGlobalSubmit === 'true' || form.hasAttribute('data-no-global-submit')) return;
    const submitter = e.submitter || form.querySelector('button[type="submit"],input[type="submit"]');
    const label = submitter ? (submitter.textContent || submitter.value || '') : '';
    const [msg, sub] = inferMessage(label, form.action || '');
    const useSignalOverlay = form.dataset.signalProcessing === 'true' || form.hasAttribute('data-signal-processing');
    if(form.dataset.uxSubmitting === '1'){
      e.preventDefault();
      return false;
    }
    if(!form.checkValidity || form.checkValidity()){
      form.dataset.uxSubmitting = '1';
      form.classList.add('form-is-submitting');
      form.querySelectorAll('button[type="submit"],input[type="submit"]').forEach(function(btn){
        btn.classList.add('is-loading');
        btn.setAttribute('aria-busy','true');
        btn.dataset.originalText = btn.dataset.originalText || (btn.textContent || btn.value || '');
        if(btn.tagName === 'BUTTON' && !btn.querySelector('.ux-loading-label')){
          const span = document.createElement('span');
          span.className = 'ux-loading-label sr-only';
          span.textContent = useSignalOverlay ? 'Processing signal' : 'Working';
          btn.appendChild(span);
        }
      });
      if(useSignalOverlay){
        window.setTimeout(function(){ setBusy(true, msg, sub); }, 120);
      }
      // If validation or network cancels in-page, recover controls after a sensible delay.
      window.setTimeout(function(){
        if(document.visibilityState === 'visible'){
          form.dataset.uxSubmitting = '0';
          form.classList.remove('form-is-submitting');
          form.querySelectorAll('.is-loading').forEach(function(btn){
            btn.classList.remove('is-loading');
            btn.removeAttribute('aria-busy');
          });
          if(useSignalOverlay) setBusy(false);
        }
      }, 10000);
    }
  }, true);

  // Field validation microcopy: add subtle error helper near invalid inputs.
  document.addEventListener('invalid', function(e){
    const field = e.target;
    if(!field || !field.classList) return;
    field.classList.add('field-invalid');
    const label = field.closest('label') || field.parentElement;
    if(label && !label.querySelector('.field-error-hint')){
      const hint = document.createElement('small');
      hint.className = 'field-error-hint';
      hint.textContent = field.validationMessage || 'Please check this field.';
      label.appendChild(hint);
    }
  }, true);
  document.addEventListener('input', function(e){
    const field = e.target;
    if(!field || !field.classList) return;
    field.classList.remove('field-invalid');
    const label = field.closest('label') || field.parentElement;
    const hint = label ? label.querySelector('.field-error-hint') : null;
    if(hint) hint.remove();
  });

  // Skeleton loading states for data-heavy regions. Markup remains normal after load.
  function enhanceEmptyOrSlowRegions(){
    document.querySelectorAll('[data-skeleton], .world-panel, .card, .bank-toolbar').forEach(function(region, idx){
      if(region.dataset.skeletonReady === '1') return;
      region.dataset.skeletonReady = '1';
      if(idx > 10) return;
      region.classList.add('ux-reveal');
    });
  }
  enhanceEmptyOrSlowRegions();

  // Reveal animations for loaded content, restrained for command software.
  if('IntersectionObserver' in window && !prefersReduced){
    const observer = new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if(entry.isIntersecting){
          entry.target.classList.add('ux-visible');
          observer.unobserve(entry.target);
        }
      });
    }, {threshold: 0.08});
    document.querySelectorAll('.card,.world-card,.world-panel,.stat-card,.phase4-tile,.signal-sheet,.bank-toolbar,.table-wrap').forEach(function(el){
      el.classList.add('ux-reveal');
      observer.observe(el);
    });
  } else {
    document.querySelectorAll('.ux-reveal').forEach(function(el){ el.classList.add('ux-visible'); });
  }

  // Table row hover actions and search feedback.
  document.querySelectorAll('table').forEach(function(table){
    table.classList.add('ux-table');
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(function(row){ row.tabIndex = row.tabIndex < 0 ? 0 : row.tabIndex; });
  });

  // Add live count feedback to existing generated table filters if present.
  document.querySelectorAll('.world-table-tools').forEach(function(panel){
    if(panel.querySelector('.ux-filter-count')) return;
    const count = document.createElement('span');
    count.className = 'ux-filter-count';
    count.setAttribute('aria-live','polite');
    panel.appendChild(count);
    const input = panel.querySelector('input[type="search"]');
    const wrapper = panel.nextElementSibling;
    const table = wrapper ? wrapper.querySelector('table') : null;
    if(!input || !table) return;
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    function refresh(){
      const visible = rows.filter(function(r){ return r.style.display !== 'none'; }).length;
      count.textContent = visible + ' of ' + rows.length + ' records shown';
    }
    input.addEventListener('input', function(){ window.setTimeout(refresh, 0); });
    refresh();
  });

  // Action confirmations for irreversible-looking buttons, without blocking normal work.
  document.addEventListener('click', function(e){
    const el = e.target.closest('button,a');
    if(!el || el.dataset.confirmed === '1' || el.dataset.noConfirm === 'true') return;
    const txt = (el.textContent || '').trim().toLowerCase();
    const risky = txt.includes('delete') || txt.includes('remove') || txt.includes('revoke') || txt.includes('recall');
    if(!risky) return;
    const ok = window.confirm('Confirm this action. It will be recorded in the audit trail.');
    if(!ok){ e.preventDefault(); e.stopPropagation(); }
    else { el.dataset.confirmed = '1'; }
  }, true);

  // Keyboard polish: slash focuses first visible search, Escape clears it.
  document.addEventListener('keydown', function(e){
    if(e.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName)){
      const search = document.querySelector('input[type="search"]:not([disabled])');
      if(search){ e.preventDefault(); search.focus(); }
    }
    if(e.key === 'Escape' && /input|textarea/i.test(document.activeElement.tagName)){
      if(document.activeElement.value){ document.activeElement.value = ''; document.activeElement.dispatchEvent(new Event('input',{bubbles:true})); }
    }
  });

  // Native alert fallback becomes a toast for non-critical notices where possible.
  const nativeAlert = window.alert;
  window.alert = function(message){
    if(toastStack && typeof message === 'string' && message.length < 180){
      window.showToast('Attention', message, null, 'info');
      return;
    }
    nativeAlert(message);
  };
})();
