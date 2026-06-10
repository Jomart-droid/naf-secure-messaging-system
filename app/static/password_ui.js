// NMS_PASSWORD_UI_UPGRADE: visible password toggles + password strength meters.
(function(){
  'use strict';

  function ready(fn){
    if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  function isLoginPassword(input){
    var form = input.closest('form');
    var autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    var name = (input.getAttribute('name') || '').toLowerCase();
    var id = (input.id || '').toLowerCase();
    var action = form ? (form.getAttribute('action') || '').toLowerCase() : '';
    var formText = form ? ((form.id || '') + ' ' + (form.className || '')).toLowerCase() : '';
    return autocomplete === 'current-password' || name === 'current_password' || action.indexOf('login') !== -1 || formText.indexOf('login') !== -1 || (id === 'password' && document.body.classList.contains('auth-body'));
  }

  function isConfirmationPassword(input){
    var name = (input.getAttribute('name') || '').toLowerCase();
    var id = (input.id || '').toLowerCase();
    var placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    return name.indexOf('confirm') !== -1 || id.indexOf('confirm') !== -1 || placeholder.indexOf('confirm') !== -1;
  }

  function shouldShowStrength(input){
    if(input.dataset.noStrength === 'true') return false;
    if(isLoginPassword(input)) return false;
    if(isConfirmationPassword(input)) return false;
    return true;
  }

  function makeEyeIcon(hidden){
    return hidden
      ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg><span>Show</span>'
      : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M17.94 17.94A10.8 10.8 0 0 1 12 19C6 19 2 12 2 12a18.6 18.6 0 0 1 5.06-5.94"/><path d="M9.9 4.24A10.2 10.2 0 0 1 12 4c6 0 10 8 10 8a18.7 18.7 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 0 1-4.24-4.24"/><path d="M3 3l18 18"/></svg><span>Hide</span>';
  }

  function scorePassword(value){
    var checks = {
      length: value.length >= 8,
      long: value.length >= 12,
      lower: /[a-z]/.test(value),
      upper: /[A-Z]/.test(value),
      number: /\d/.test(value),
      special: /[^A-Za-z0-9]/.test(value),
      noSpace: value.length > 0 && !/\s/.test(value),
      notCommon: !/^(password|password123|admin|admin123|naf123|12345678|qwerty|letmein)$/i.test(value)
    };
    var score = 0;
    if(checks.length) score++;
    if(checks.lower && checks.upper) score++;
    if(checks.number) score++;
    if(checks.special) score++;
    if(checks.long && checks.notCommon && checks.noSpace) score++;

    if(!value) return {score:0, label:'Enter a password', className:'empty', checks:checks};
    if(score <= 1) return {score:1, label:'Weak', className:'weak', checks:checks};
    if(score === 2) return {score:2, label:'Fair', className:'fair', checks:checks};
    if(score === 3 || score === 4) return {score:4, label:'Good', className:'good', checks:checks};
    return {score:5, label:'Strong', className:'strong', checks:checks};
  }

  function strengthMarkup(){
    return '<div class="pw-strength-head"><span>Password strength</span><strong data-pw-label>Enter a password</strong></div>' +
      '<div class="pw-strength-bar" aria-hidden="true"><span data-pw-bar></span></div>' +
      '<ul class="pw-strength-rules">' +
      '<li data-rule="length">At least 8 characters</li>' +
      '<li data-rule="case">Uppercase and lowercase letters</li>' +
      '<li data-rule="number">At least one number</li>' +
      '<li data-rule="special">At least one special character</li>' +
      '</ul>';
  }

  function updateStrength(input, meter){
    var result = scorePassword(input.value || '');
    meter.className = 'pw-strength-meter ' + result.className;
    meter.querySelector('[data-pw-label]').textContent = result.label;
    meter.querySelector('[data-pw-bar]').style.width = (result.score * 20) + '%';
    meter.querySelector('[data-rule="length"]').classList.toggle('ok', result.checks.length);
    meter.querySelector('[data-rule="case"]').classList.toggle('ok', result.checks.lower && result.checks.upper);
    meter.querySelector('[data-rule="number"]').classList.toggle('ok', result.checks.number);
    meter.querySelector('[data-rule="special"]').classList.toggle('ok', result.checks.special);
  }

  function enhancePassword(input){
    if(input.dataset.passwordEnhanced === 'true') return;
    input.dataset.passwordEnhanced = 'true';

    var wrapper = document.createElement('div');
    wrapper.className = 'password-input-wrap';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);
    input.classList.add('password-with-toggle');

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'password-toggle-btn';
    btn.setAttribute('aria-label', 'Show password');
    btn.innerHTML = makeEyeIcon(true);
    wrapper.appendChild(btn);

    btn.addEventListener('click', function(ev){
      ev.preventDefault();
      var hidden = input.type === 'password';
      input.type = hidden ? 'text' : 'password';
      btn.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
      btn.innerHTML = makeEyeIcon(!hidden);
      input.focus({preventScroll:true});
    });

    if(shouldShowStrength(input)){
      var meter = document.createElement('div');
      meter.className = 'pw-strength-meter empty';
      meter.setAttribute('aria-live', 'polite');
      meter.innerHTML = strengthMarkup();
      wrapper.insertAdjacentElement('afterend', meter);
      input.addEventListener('input', function(){ updateStrength(input, meter); });
      updateStrength(input, meter);
    }
  }

  ready(function(){
    document.querySelectorAll('input[type="password"]').forEach(enhancePassword);
  });
})();
