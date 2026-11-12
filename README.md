# LightAccountHive — Google sign-in + Hive Lite (Cloudflare Worker)

This branch **replaces** the old shared-Hive-posting-authority model with the
Syncad `lite_account` identity protocol. It is an **opt-in staging implementation**:
login works once configured; **L1 writes are disabled by default**. Nothing is
deployed to Cloudflare by merging this code.

## What works

- Google Identity Services (GIS) sign-in, with **Google ID token verification** using
  Google's rotating JWKS, correct audience/issuer, and one-time browser login nonce.
- Same-origin, HttpOnly/Secure session cookies, seven-day hashed sessions in D1,
  session revocation, and origin checks on POST requests.
- One user per Google `sub`; the email address is **not** an identifier or stored.
- Automatic **custodial** Lite owner/posting key generation: each user receives two
  independent secp256k1 keys encrypted with AES-256-GCM and stored in D1. The private
  keys are not sent to the browser.
- Validate Lite names, check the public Lite index **and** Hive L1 name availability,
  then submit Syncad's unsigned-L2 `register_account` transaction as a Hive
  `custom_json` signed by the Gate's **posting** key.
- A small same-origin demo at `/` for Google sign-in and account reservation.
- Cloudflare Turnstile verification for the **RC-consuming** registration routes.

## What is intentionally NOT implemented

- **Social operations, post attestation, posting, transfers, and key rotation**.
  These require exact `l2_framework` canonical JCS + chain-specific digest +
  secp256k1 recovery signature support. Do not improvise the signing algorithm.
- Proof that the indexed name belongs to our stored keys. `lite.lookup_accounts`
  proves **name existence**, not authority ownership or an **applied** receipt.
  Registration stays `submitted` until an independently verified on-chain authority
  / receipt mechanism is implemented.
- Automated recovery, key export, encryption-key rotation, L1 RC quota accounting,
  or a complete anti-abuse service. A production release needs these.

The original `/register` and `/sign-and-broadcast` endpoints are **removed**.
**IMPORTANT:** replacing the Worker **does not revoke** the Lite public keys that
the old project previously added to the L1 Gate's `posting` authority. You must
**review and revoke those keys on-chain** using the account's proper authority
before using it for production.

## Architecture

```text
Google Identity Services (browser)
              |
              v
        Cloudflare Worker  <----> Cloudflare D1 (Google sub, sessions, encrypted keys)
              |
         Hive RPC             Syncad Lite RPC
              |                      |
       L1 custom_json         lite.get_info / lookup_accounts
       id: lite_account       (read-only)
              |
        l2_framework + lite_account (Syncad node)
```

This is **custodial by design**. A compromised Worker + encryption secret could
control customers' Lite identities. Google login does not confer autonomous
cryptographic ownership. Keep the encryption secret out of Git and provide an
audited export/rotation/recovery path before wide release.

## Configure locally

Requires Node 22+ and a Cloudflare account for eventual deployment.

```bash
npm install
npm run check
npx wrangler d1 create hive-light-accounts
```

Paste the returned `database_id` into `wrangler.json`, replacing the all-zero
placeholder. Then:

```bash
npx wrangler d1 migrations apply DB --local
npx wrangler d1 migrations apply DB --remote
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put KEY_ENCRYPTION_KEY
npx wrangler secret put GATE_POSTING_KEY
npx wrangler secret put TURNSTILE_SECRET
```

Generate the base64 encryption secret locally, do **not** commit it:

```bash
openssl rand -base64 32
```

In `wrangler.json`, configure:

- `HIVE_MAIN_ACCOUNT`: the **dedicated** Hive account paying RC for registration.
  Never use a shared posting authority with user keys.
- `LITE_RPC_URL`: the Syncad JSON-RPC endpoint that serves `lite.get_info`.
  The provided default `https://api.syncad.com` is a candidate; **verify that
  URL works for JSON-RPC**, independently of its Swagger documentation page.
- `HIVE_NODE`: your trusted Hive RPC endpoint.
- `TURNSTILE_SITE_KEY`: Cloudflare Turnstile widget public site key, with
  your Worker hostname explicitly in the widget's allowed hostnames.
- `ENABLE_L1_WRITES`: keep `false` during development. Change to `true`
  **only after** testing the RPC endpoints, D1 migration, separate Gate posting
  key and Turnstile setup on a controlled environment.

Google Cloud Console: create an **OAuth 2.0 Web client** for Google Identity
Services, and register your Worker **origin** (scheme + host) under
**Authorized JavaScript origins**. The JavaScript callback flow does not need
an OAuth client secret or a redirect URI. The Google *client ID* may be public;
it is stored as a Worker secret here to keep configuration uniform.

For `wrangler dev`, create a **local-only** `.dev.vars` with the required
values, rather than expecting remote secrets to populate local development.
The file is gitignored.

```bash
npm run dev
# open http://localhost:8787/
# when ready:
npm run deploy
```

Use a **same-origin frontend** for the demo and for the first production
integration. Session cookies are `SameSite=Lax` and must not depend on
third-party cookie support. To integrate HiveLine, either host a same-origin
app/API or add a separate reviewed OAuth/session architecture.

## API

| Route | Purpose |
|---|---|
| `GET /` | Same-origin Google login demo |
| `GET /api/health` | Worker status |
| `GET /api/public/config` | Public Google Client ID and registration enablement |
| `GET /api/auth/challenge` | Nonce cookie for Google ID token login |
| `POST /api/auth/google` | Verify Google ID token; create HttpOnly session |
| `GET /api/auth/me` | Current session + Lite account status |
| `POST /api/auth/logout` | Revoke session |
| `GET /api/lite/info` | Proxy only `lite.get_info` read method |
| `GET /api/lite/account` | Current user's reserved Lite identity |
| `POST /api/lite/register` | Register once; requires Turnstile + Gate writes enabled |
| `POST /api/lite/retry` | Retry pending broadcast **only** if name is absent on-chain |
| `POST /api/lite/refresh` | Check index visibility, **not** authority ownership |

Never expose encrypted key columns or the raw Google `sub` to clients.
The private keys are not available through HTTP routes.

## On-chain registration format

The `hive/lite_account` integration tests show `register_account` requires
**no L2 signature** on initial registration; the Hive broadcaster authorizes
the transaction. The Worker sends a regular L1 `custom_json` operation:

```json
{
  "required_auths": [],
  "required_posting_auths": ["YOUR_GATE"],
  "id": "lite_account",
  "json": "{\"app\":\"lite_account\",\"version\":1,\"operations\":[{\"method\":\"register_account\",\"args\":{\"name\":\"alice\",\"owner\":{\"weight_threshold\":1,\"key_auths\":[{\"member\":{\"type\":\"secp256k1\",\"value\":\"STM...\"},\"weight\":1}],\"account_auths\":[]},\"posting\":{\"weight_threshold\":1,\"key_auths\":[{\"member\":{\"type\":\"secp256k1\",\"value\":\"STM...\"},\"weight\":1}],\"account_auths\":[]}}}],\"expiration\":\"2026-11-12T18:00:00\",\"signatures\":[]}"
}
```

The `json` property above is a **string**, not an object; expiration and keys
are illustrative. The Worker constructs it programmatically in
`src/protocol.ts`.

## Security / production checklist

Use a **separate**, minimally funded Gate account with monitored RC. Restrict
requests to a trusted origin; configure Cloudflare WAF/rate limits, Turnstile,
and monitoring before enabling sponsorship. Rotate encryption keys using a
versioned migration strategy, not by overwriting `KEY_ENCRYPTION_KEY` in place.
Keep multiple encrypted, access-controlled backups of the D1 data **and** the
matching encryption secret, stored separately. Review the L2 receipt and
authority-verification requirements before enabling other write operations.
