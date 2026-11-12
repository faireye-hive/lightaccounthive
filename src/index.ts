import type { Env, SessionUser, LiteAccountRow } from './types';
import { verifyGoogleIdToken, readCookie, writeCookie, clearCookie, requireSameOrigin } from './auth';
import { randomToken, createLiteKeyPair, encryptPrivateKey } from './crypto';
import { upsertUser, createSession, sessionUser, revokeSession, findLiteAccount, saveLiteAccount, setLiteStatus } from './database';
import { validLiteName } from './protocol';
import { assertNameAvailable, broadcastRegistration, isRegistered, liteRpc } from './hive';
import { DEMO_HTML, DEMO_JS } from './ui';

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const MAX_JSON_BYTES = 12_000;
const NONCE_AGE = 10 * 60;
const SESSION_AGE = 7 * 24 * 60 * 60;

function json(data: unknown, status = 200, cookies: string[] = []): Response {
  const headers = new Headers(JSON_HEADERS);
  for (const cookie of cookies) headers.append('Set-Cookie', cookie);
  return new Response(JSON.stringify(data), { status, headers });
}
function fail(message: string, code = 400): Response { return json({ error: message }, code); }
async function input(request: Request): Promise<Record<string, unknown>> {
  const raw = await request.text();
  if (raw.length > MAX_JSON_BYTES) throw new Error('Request body too large');
  const value: unknown = JSON.parse(raw);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid JSON object');
  return value as Record<string, unknown>;
}
function accountView(account: LiteAccountRow | null) {
  if (!account) return null;
  // Do not expose the encrypted keys, Google subject, or key management internals.
  return {
    did: `did:lite:${account.name}`,
    name: account.name,
    status: account.status,
    txId: account.tx_id,
    createdAt: account.created_at
  };
}
async function authenticated(request: Request, env: Env): Promise<SessionUser | null> {
  const token = readCookie(request, 'session');
  return token ? sessionUser(env.DB, token) : null;
}
function writesReady(env: Env): boolean {
  return env.ENABLE_L1_WRITES === 'true' &&
    !!env.HIVE_MAIN_ACCOUNT && !!env.GATE_POSTING_KEY &&
    !!env.KEY_ENCRYPTION_KEY && !!env.TURNSTILE_SECRET &&
    !!env.TURNSTILE_SITE_KEY && !!env.LITE_RPC_URL;
}
async function checkTurnstile(request: Request, env: Env, token: unknown): Promise<boolean> {
  if (!env.TURNSTILE_SECRET || typeof token !== 'string' || token.length > 2048) return false;
  const payload = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token });
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) payload.set('remoteip', ip);
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST', body: payload, signal: AbortSignal.timeout(10000)
  });
  if (!res.ok) return false;
  const result = await res.json() as { success?: boolean; hostname?: string };
  // A production Turnstile widget must be restricted to the Worker hostname.
  const hostname = new URL(request.url).hostname;
  return result.success === true && result.hostname === hostname;
}

async function register(request: Request, env: Env, user: SessionUser): Promise<Response> {
  if (!writesReady(env)) return fail('Registration is disabled until Gate, D1 and Turnstile are configured', 503);
  const body = await input(request);
  if (typeof body.name !== 'string' || !validLiteName(body.name)) {
    return fail('Name must be 3-16 lowercase Hive-compatible characters (segments at least 3)');
  }
  if (await findLiteAccount(env.DB, user.sub)) return fail('This Google account already has a reserved Lite identity', 409);
  if (!await checkTurnstile(request, env, body.turnstileToken)) return fail('Turnstile verification failed', 403);
  await assertNameAvailable(env, body.name);
  const owner = createLiteKeyPair();
  const posting = createLiteKeyPair();
  const secret = env.KEY_ENCRYPTION_KEY!;
  const now = Math.floor(Date.now() / 1000);
  const record: LiteAccountRow = {
    google_sub: user.sub,
    name: body.name,
    owner_public: owner.publicKey,
    posting_public: posting.publicKey,
    owner_ciphertext: await encryptPrivateKey(owner.privateKey, secret, user.sub, body.name, 'owner'),
    posting_ciphertext: await encryptPrivateKey(posting.privateKey, secret, user.sub, body.name, 'posting'),
    status: 'pending', tx_id: null, created_at: now, updated_at: now
  };
  try {
    await saveLiteAccount(env.DB, record);  // unique subject + unique name
  } catch {
    return fail('Name or Google account already reserved', 409);
  }
  try {
    const txId = await broadcastRegistration(env, record.name, record.owner_public, record.posting_public);
    await setLiteStatus(env.DB, user.sub, 'submitted', txId);
    return json({ account: accountView({ ...record, status: 'submitted', tx_id: txId }), note: 'Broadcast submitted; indexing and authority confirmation are still pending.' }, 202);
  } catch {
    // Keep the encrypted keys and pending record so the identity is never silently replaced.
    return fail('Broadcast not confirmed. Identity reserved locally; check the chain before retrying.', 502);
  }
}

async function retry(request: Request, env: Env, user: SessionUser): Promise<Response> {
  if (!writesReady(env)) return fail('Writes are disabled', 503);
  const account = await findLiteAccount(env.DB, user.sub);
  if (!account || account.status !== 'pending') return fail('No pending registration to retry', 409);
  const body = await input(request);
  if (!await checkTurnstile(request, env, body.turnstileToken)) return fail('Turnstile verification failed', 403);
  // A timeout may mean the first broadcast actually succeeded.
  if (await isRegistered(env, account.name)) {
    return fail('Name now exists on-chain; manual authority verification is required before retrying', 409);
  }
  const txId = await broadcastRegistration(env, account.name, account.owner_public, account.posting_public);
  await setLiteStatus(env.DB, user.sub, 'submitted', txId);
  return json({ account: accountView({ ...account, status: 'submitted', tx_id: txId }) }, 202);
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url), path = url.pathname;
  if (path === '/' && request.method === 'GET') {
    return new Response(DEMO_HTML, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; script-src 'self' https://accounts.google.com/gsi/client https://challenges.cloudflare.com; style-src 'unsafe-inline' https://accounts.google.com/gsi/style; img-src 'self' https://lh3.googleusercontent.com data:; connect-src 'self' https://accounts.google.com https://challenges.cloudflare.com; frame-src https://accounts.google.com https://challenges.cloudflare.com; base-uri 'none'; form-action 'self'"
      }
    });
  }
  if (path === '/app.js' && request.method === 'GET') {
    return new Response(DEMO_JS, { headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
  }
  if (path === '/api/health' && request.method === 'GET') return json({ ok: true, service: 'lightaccounthive', version: 2 });
  if (path === '/api/public/config' && request.method === 'GET') return json({
    googleClientId: env.GOOGLE_CLIENT_ID || null,
    registrationEnabled: writesReady(env),
    turnstileSiteKey: env.TURNSTILE_SITE_KEY || null
  });
  if (path === '/api/lite/info' && request.method === 'GET') {
    return json(await liteRpc(env, 'get_info', {}));
  }
  if (path === '/api/auth/challenge' && request.method === 'GET') {
    const nonce = randomToken(24);
    return json({ nonce }, 200, [writeCookie(request, 'oauth_nonce', nonce, NONCE_AGE)]);
  }
  if (request.method !== 'GET' && !requireSameOrigin(request)) return fail('Cross-origin requests are not allowed', 403);

  if (path === '/api/auth/google' && request.method === 'POST') {
    if (!env.GOOGLE_CLIENT_ID) return fail('Google client ID not configured', 503);
    const nonce = readCookie(request, 'oauth_nonce');
    if (!nonce) return fail('Login challenge missing or expired', 403);
    const body = await input(request);
    if (typeof body.credential !== 'string' || body.credential.length > 10000) return fail('Invalid Google credential');
    let identity;
    try {
      identity = await verifyGoogleIdToken(body.credential, env.GOOGLE_CLIENT_ID, nonce);
    } catch { return fail('Google ID token verification failed', 401); }
    await upsertUser(env.DB, identity);
    const token = await createSession(env.DB, identity.sub);
    return json({ user: identity, account: accountView(await findLiteAccount(env.DB, identity.sub)) }, 200, [
      clearCookie(request, 'oauth_nonce'), writeCookie(request, 'session', token, SESSION_AGE)
    ]);
  }

  if (path === '/api/auth/logout' && request.method === 'POST') {
    const token = readCookie(request, 'session');
    if (token) await revokeSession(env.DB, token);
    return json({ ok: true }, 200, [clearCookie(request, 'session')]);
  }

  const user = await authenticated(request, env);
  if (path === '/api/auth/me' && request.method === 'GET') {
    return user ? json({ user: { name: user.name, picture: user.picture }, account: accountView(await findLiteAccount(env.DB, user.sub)) })
      : fail('Not authenticated', 401);
  }
  if (!user) return fail('Not authenticated', 401);
  if (path === '/api/lite/account' && request.method === 'GET') {
    return json({ account: accountView(await findLiteAccount(env.DB, user.sub)) });
  }
  if (path === '/api/lite/register' && request.method === 'POST') return register(request, env, user);
  if (path === '/api/lite/retry' && request.method === 'POST') return retry(request, env, user);
  if (path === '/api/lite/refresh' && request.method === 'POST') {
    const account = await findLiteAccount(env.DB, user.sub);
    if (!account) return fail('No Lite account', 404);
    const indexed = await isRegistered(env, account.name);
    // Name existence alone DOES NOT prove that our public keys became the authority.
    return json({ account: accountView(account), indexed, authorityVerified: false });
  }
  return fail('Route not found', 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') return new Response(null, { status: 405, headers: JSON_HEADERS });
    try {
      return await route(request, env);
    } catch (error) {
      console.error('Worker request failed', error instanceof Error ? error.name : 'UnknownError');
      return fail('Request failed. Check configuration or upstream RPC availability.', 502);
    }
  }
};
