import { PrivateKey } from 'hive-tx';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function randomToken(bytes = 32): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return base64url(data);
}

export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function unbase64url(encoded: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error('Invalid base64url');
  const text = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(text.padEnd(Math.ceil(text.length / 4) * 4, '='));
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}

export async function sha256(text: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))));
}

/** KEY_ENCRYPTION_KEY: one 32-byte secret encoded in base64url or base64. */
async function encryptionKey(secret: string): Promise<CryptoKey> {
  const bytes = unbase64url(secret.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''));
  if (bytes.byteLength !== 32) throw new Error('KEY_ENCRYPTION_KEY must be 32 bytes');
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function aad(subject: string, name: string, role: string): Uint8Array {
  return encoder.encode(`lite:v1:${subject}:${name}:${role}`);
}

export async function encryptPrivateKey(
  wif: string, secret: string, subject: string, name: string, role: 'owner' | 'posting'
): Promise<string> {
  const key = await encryptionKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const result = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(subject, name, role) },
    key,
    encoder.encode(wif)
  );
  return `v1.${base64url(iv)}.${base64url(new Uint8Array(result))}`;
}

/** Internal-only helper for future authenticated L2 signing. Never return WIF to clients. */
export async function decryptPrivateKey(
  cipher: string, secret: string, subject: string, name: string, role: 'owner' | 'posting'
): Promise<string> {
  const [version, ivText, ciphertext] = cipher.split('.');
  if (version !== 'v1' || !ivText || !ciphertext) throw new Error('Unsupported encrypted key');
  const key = await encryptionKey(secret);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unbase64url(ivText), additionalData: aad(subject, name, role) },
    key,
    unbase64url(ciphertext)
  );
  return decoder.decode(plaintext);
}

export function createLiteKeyPair(): { publicKey: string; privateKey: string } {
  const key = PrivateKey.randomKey();
  return { publicKey: key.createPublic().toString(), privateKey: key.toString() };
}
