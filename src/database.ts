import type { Env, GoogleIdentity, LiteAccountRow, SessionUser } from './types';
import { randomToken, sha256 } from './crypto';

const SESSION_AGE_SECONDS = 7 * 24 * 60 * 60;

export async function upsertUser(db: Env['DB'], user: GoogleIdentity): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db.prepare(`INSERT INTO users (google_sub, display_name, picture_url, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(google_sub) DO UPDATE SET display_name=excluded.display_name,
      picture_url=excluded.picture_url, updated_at=excluded.updated_at`)
    .bind(user.sub, user.name, user.picture, now, now).run();
}

export async function createSession(db: Env['DB'], subject: string): Promise<string> {
  const token = randomToken();
  const now = Math.floor(Date.now() / 1000);
  await db.prepare('INSERT INTO sessions (token_hash, google_sub, expires_at, created_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(token), subject, now + SESSION_AGE_SECONDS, now).run();
  return token;
}

export async function sessionUser(db: Env['DB'], token: string): Promise<SessionUser | null> {
  if (!/^[A-Za-z0-9_-]{40,64}$/.test(token)) return null;
  const row = await db.prepare(`SELECT u.google_sub AS sub, u.display_name AS name,
    u.picture_url AS picture, s.expires_at AS expiresAt FROM sessions s
    JOIN users u ON u.google_sub=s.google_sub
    WHERE s.token_hash=? AND s.expires_at>?`)
    .bind(await sha256(token), Math.floor(Date.now() / 1000))
    .first<SessionUser>();
  return row ?? null;
}

export async function revokeSession(db: Env['DB'], token: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
}

export async function findLiteAccount(db: Env['DB'], subject: string): Promise<LiteAccountRow | null> {
  return (await db.prepare('SELECT * FROM lite_accounts WHERE google_sub=?')
    .bind(subject).first<LiteAccountRow>()) ?? null;
}

export async function saveLiteAccount(db: Env['DB'], account: LiteAccountRow): Promise<void> {
  await db.prepare(`INSERT INTO lite_accounts
    (google_sub, name, owner_public, posting_public, owner_ciphertext,
     posting_ciphertext, status, tx_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(account.google_sub, account.name, account.owner_public, account.posting_public,
      account.owner_ciphertext, account.posting_ciphertext, account.status, account.tx_id,
      account.created_at, account.updated_at).run();
}

export async function setLiteStatus(
  db: Env['DB'], subject: string, status: LiteAccountRow['status'], txId?: string
): Promise<void> {
  await db.prepare('UPDATE lite_accounts SET status=?, tx_id=COALESCE(?, tx_id), updated_at=? WHERE google_sub=?')
    .bind(status, txId ?? null, Math.floor(Date.now() / 1000), subject).run();
}
