export interface Env {
  DB: D1Database;
  GOOGLE_CLIENT_ID?: string;
  KEY_ENCRYPTION_KEY?: string;
  GATE_POSTING_KEY?: string;
  HIVE_MAIN_ACCOUNT?: string;
  HIVE_NODE?: string;
  LITE_RPC_URL?: string;
  ENABLE_L1_WRITES?: string;
  TURNSTILE_SECRET?: string;
  TURNSTILE_SITE_KEY?: string;
}

export interface GoogleIdentity {
  sub: string;
  name: string;
  picture: string | null;
}

export interface SessionUser extends GoogleIdentity {
  expiresAt: number;
}

export interface LiteAccountRow {
  google_sub: string;
  name: string;
  owner_public: string;
  posting_public: string;
  owner_ciphertext: string;
  posting_ciphertext: string;
  status: 'pending' | 'submitted' | 'active';
  tx_id: string | null;
  created_at: number;
  updated_at: number;
}
