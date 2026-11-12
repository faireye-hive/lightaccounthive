-- Custodial Lite identities: encrypted keys never leave the server.
-- Cloudflare D1 SQLite; apply via wrangler d1 migrations apply DB.
CREATE TABLE IF NOT EXISTS users (
  google_sub TEXT PRIMARY KEY NOT NULL,
  display_name TEXT NOT NULL,
  picture_url TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY NOT NULL,
  google_sub TEXT NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiration ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_google_sub ON sessions(google_sub);

CREATE TABLE IF NOT EXISTS lite_accounts (
  google_sub TEXT PRIMARY KEY NOT NULL REFERENCES users(google_sub) ON DELETE CASCADE,
  name TEXT UNIQUE NOT NULL,
  owner_public TEXT NOT NULL,
  posting_public TEXT NOT NULL,
  owner_ciphertext TEXT NOT NULL,
  posting_ciphertext TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','submitted','active')),
  tx_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lite_accounts_name ON lite_accounts(name);
