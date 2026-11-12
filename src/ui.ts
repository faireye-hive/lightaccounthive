/** Minimal same-origin demo; intended for testing the Worker before embedding in HiveLine. */
export const DEMO_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightAccountHive · Google + Hive Lite</title>
<style>
:root{font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;color:#222;background:#f7f7f7}
*{box-sizing:border-box}body{margin:0;padding:48px 16px}.wrap{max-width:620px;margin:auto}
header{margin-bottom:24px}h1{font-size:1.7rem;margin:0;letter-spacing:-.03em}
p{color:#606060}section{background:white;border:1px solid #e5e5e5;border-radius:16px;padding:25px;margin:14px 0;box-shadow:0 3px 14px #00000008}
label{display:block;font-weight:600;margin:14px 0 7px}
input{width:100%;border-radius:9px;border:1px solid #cacaca;font:inherit;padding:11px 12px}
button{padding:10px 16px;border:1px solid #d0d0d0;border-radius:9px;background:#171717;color:white;cursor:pointer;font:inherit}
button:disabled{opacity:.45;cursor:not-allowed}.muted{color:#777;font-size:.9rem}#status{white-space:pre-wrap;overflow-wrap:anywhere}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:15px}
.hidden{display:none}strong{color:#272727}code{font-family:ui-monospace,monospace;overflow-wrap:anywhere}
</style></head><body><div class="wrap"><header><h1>LightAccountHive</h1>
<p>Google sign-in + Hive Lite identity, without displaying private keys.</p></header>
<section id="signIn"><h2>Sign in</h2><p class="muted">Use your Google account to get started.</p><div id="googleButton"></div></section>
<section id="dashboard" class="hidden"><h2>Account</h2><p id="identity"></p>
<div id="registration" class="hidden"><form id="registerForm"><label for="name">Choose a Lite name</label>
<input id="name" name="name" required minlength="3" maxlength="16" autocomplete="off" pattern="[a-z0-9.-]+" placeholder="e.g. brave-otter">
<p class="muted">3–16 lowercase characters; Hive-compatible name, not an existing Hive account.</p>
<div id="turnstile"></div><div class="row"><button type="submit">Register Lite identity</button></div></form></div>
<div class="row"><button id="refresh" type="button">Check indexing</button><button id="retry" type="button" class="hidden">Retry pending broadcast</button><button id="logout" type="button">Sign out</button></div>
</section><section><h2>Status</h2><div id="status" role="status" aria-live="polite">Loading…</div></section>
<p class="muted">Prototype: registering does not yet enable Lite signed posting or profile editing. No blockchain writes until explicitly enabled in Wrangler.</p>
</div><script src="https://accounts.google.com/gsi/client" async defer></script>
<script src="/app.js" defer></script></body></html>`;

export const DEMO_JS = `
const $ = (id) => document.getElementById(id);
let settings = null;
let turnstileToken = '';
let widgetId = null;
const setStatus = (msg) => { $('status').textContent = msg; };
async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    credentials: 'same-origin',
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) }
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
  return data;
}
function showAccount(user, account) {
  $('signIn').classList.add('hidden');
  $('dashboard').classList.remove('hidden');
  const label = account ? account.did + ' (' + account.status + ')' : 'No Lite identity registered yet';
  $('identity').textContent = 'Signed in as ' + user.name + ' · ' + label;
  $('registration').classList.toggle('hidden', !!account || !settings.registrationEnabled);
  $('retry').classList.toggle('hidden', !account || account.status !== 'pending');
  $('refresh').disabled = !account;
  if (!account && !settings.registrationEnabled) setStatus('Sign-in works. Lite registration is disabled until deployment configuration is complete.');
  else setStatus(account ? 'Your identity is reserved; on-chain confirmation and authority checking are separate steps.' : 'Choose a Lite name to register.');
}
async function loadMe() {
  try { const data = await api('/api/auth/me'); showAccount(data.user, data.account); return true; }
  catch { return false; }
}
async function setupGoogle() {
  const { nonce } = await api('/api/auth/challenge');
  for (let i = 0; i < 100 && !(window.google && google.accounts && google.accounts.id); i++)
    await new Promise((r) => setTimeout(r, 100));
  if (!window.google?.accounts?.id) throw new Error('Google Identity script did not load');
  google.accounts.id.initialize({
    client_id: settings.googleClientId,
    nonce,
    callback: async (response) => {
      try {
        setStatus('Verifying Google identity…');
        const data = await api('/api/auth/google', {
          method: 'POST',
          body: JSON.stringify({ credential: response.credential })
        });
        showAccount(data.user, data.account);
      } catch (err) { setStatus(err.message); }
    }
  });
  google.accounts.id.renderButton($('googleButton'), { theme: 'outline', size: 'large', text: 'continue_with', width: 280 });
}
async function initTurnstile() {
  if (!settings.registrationEnabled || !settings.turnstileSiteKey) return;
  const script = document.createElement('script');
  script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  script.async = true;
  script.onload = () => {
    widgetId = turnstile.render('#turnstile', {
      sitekey: settings.turnstileSiteKey,
      callback: (token) => { turnstileToken = token; },
      'expired-callback': () => { turnstileToken = ''; }
    });
  };
  document.head.appendChild(script);
}
async function register(event, retry = false) {
  if (event) event.preventDefault();
  if (!turnstileToken) { setStatus('Complete the verification challenge first.'); return; }
  try {
    setStatus('Submitting Lite account registration…');
    const path = retry ? '/api/lite/retry' : '/api/lite/register';
    const body = retry ? { turnstileToken } : { name: $('name').value.trim(), turnstileToken };
    const data = await api(path, { method: 'POST', body: JSON.stringify(body) });
    turnstileToken = '';
    setStatus(data.note || 'Broadcast submitted. The Lite API may take time to index it.');
    await loadMe();
  } catch (err) {
    setStatus(err.message);
  } finally {
    if (widgetId !== null && window.turnstile) turnstile.reset(widgetId);
  }
}
async function start() {
  try {
    settings = await api('/api/public/config');
    await initTurnstile();
    $('registerForm').addEventListener('submit', (event) => register(event));
    $('retry').addEventListener('click', () => register(null, true));
    $('refresh').addEventListener('click', async () => {
      try {
        const data = await api('/api/lite/refresh', { method: 'POST' });
        setStatus('Indexed: ' + data.indexed + '. Authority verified: ' + data.authorityVerified + '. Registration receipt verification is still required.');
      } catch (err) { setStatus(err.message); }
    });
    $('logout').addEventListener('click', async () => {
      try { await api('/api/auth/logout', { method: 'POST' }); window.location.reload(); }
      catch (err) { setStatus(err.message); }
    });
    if (await loadMe()) return;
    setStatus(settings.googleClientId ? 'Sign in with Google to continue.' : 'Configure GOOGLE_CLIENT_ID first.');
    if (settings.googleClientId) await setupGoogle();
  } catch (err) { setStatus(err.message); }
}
start();
`;
