import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { GoogleIdentity } from './types';

const GOOGLE_JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
const encoder = new TextEncoder();

export async function verifyGoogleIdToken(
  credential: string, clientId: string, expectedNonce: string
): Promise<GoogleIdentity> {
  const { payload } = await jwtVerify(credential, GOOGLE_JWKS, {
    algorithms: ['RS256'],
    audience: clientId,
    issuer: ['https://accounts.google.com', 'accounts.google.com']
  });
  if (typeof payload.sub !== 'string' || !payload.sub ||
      typeof payload.nonce !== 'string' || !expectedNonce ||
      !timingSafeEqual(payload.nonce, expectedNonce)) {
    throw new Error('Google ID token nonce / subject invalid');
  }
  if (payload.azp && payload.azp !== clientId) throw new Error('Unexpected Google authorized party');
  const picture = typeof payload.picture === 'string' &&
    payload.picture.startsWith('https://') ? payload.picture : null;
  return {
    sub: payload.sub,
    name: typeof payload.name === 'string' ? payload.name.slice(0, 120) : 'Google user',
    picture
  };
}

function timingSafeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a), y = encoder.encode(b);
  if (x.byteLength !== y.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < x.byteLength; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

type CookieKind = 'oauth_nonce' | 'session';

function cookieName(request: Request, kind: CookieKind): string {
  return new URL(request.url).protocol === 'https:' ? `__Host-lite_${kind}` : `lite_${kind}`;
}

export function readCookie(request: Request, kind: CookieKind): string | null {
  const name = cookieName(request, kind);
  const part = (request.headers.get('Cookie') || '').split(';')
    .map((x) => x.trim())
    .find((x) => x.startsWith(name + '='));
  return part ? part.slice(name.length + 1) : null;
}

export function writeCookie(request: Request, kind: CookieKind, value: string, maxAge: number): string {
  const secure = new URL(request.url).protocol === 'https:';
  return `${cookieName(request, kind)}=${value}; HttpOnly; Path=/; SameSite=Lax; ${secure ? 'Secure; ' : ''}Max-Age=${maxAge}`;
}

export function clearCookie(request: Request, kind: CookieKind): string {
  return writeCookie(request, kind, '', 0);
}

export function requireSameOrigin(request: Request): boolean {
  const expected = new URL(request.url).origin;
  const origin = request.headers.get('Origin');
  const fetchSite = request.headers.get('Sec-Fetch-Site');
  return (!origin || origin === expected) && (!fetchSite || fetchSite === 'same-origin' || fetchSite === 'none');
}
