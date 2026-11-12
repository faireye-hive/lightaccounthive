import { Transaction, PrivateKey, config } from 'hive-tx';
import type { Env } from './types';
import { buildRegistration } from './protocol';

function jsonRpcEndpoint(env: Env): string {
  return env.HIVE_NODE || 'https://api.hive.blog';
}

export async function rpc(endpoint: string, method: string, params: unknown): Promise<unknown> {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method, params, id: 1 }),
    signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
  const data = await response.json() as { error?: { message?: string }; result?: unknown };
  if (data.error) throw new Error(data.error.message || 'RPC error');
  if (!Object.prototype.hasOwnProperty.call(data, 'result')) throw new Error('RPC result missing');
  return data.result;
}

export async function liteRpc(env: Env, method: string, params: unknown): Promise<unknown> {
  if (!env.LITE_RPC_URL) throw new Error('LITE_RPC_URL not configured');
  return rpc(env.LITE_RPC_URL, `lite.${method}`, params);
}

/** Fail closed: both the Lite index and L1 Hive must be reachable before taking a name. */
export async function assertNameAvailable(env: Env, name: string): Promise<void> {
  const entries = await liteRpc(env, 'lookup_accounts', { prefix: name, limit: 20 });
  if (!Array.isArray(entries)) throw new Error('Unexpected Lite account lookup response');
  if (entries.some((entry) => entry === `did:lite:${name}` || entry === name)) {
    throw new Error('Lite name already registered');
  }
  const accounts = await rpc(jsonRpcEndpoint(env), 'condenser_api.get_accounts', [[name]]);
  if (!Array.isArray(accounts)) throw new Error('Unexpected Hive account lookup response');
  if (accounts.length > 0) throw new Error('Name already used by a Hive account');
}

export async function isRegistered(env: Env, name: string): Promise<boolean> {
  const entries = await liteRpc(env, 'lookup_accounts', { prefix: name, limit: 20 });
  if (!Array.isArray(entries)) throw new Error('Unexpected Lite account lookup response');
  return entries.some((entry) => entry === `did:lite:${name}` || entry === name);
}

/** This is only the L1-broadcaster-authorized, zero-L2-signature registration.
 * Follow, attest, rotate, etc. need the l2_framework digest/signature implementation.
 */
export async function broadcastRegistration(
  env: Env, name: string, ownerPublic: string, postingPublic: string
): Promise<string> {
  if (env.ENABLE_L1_WRITES !== 'true') throw new Error('L1 writes are disabled');
  if (!env.GATE_POSTING_KEY || !env.HIVE_MAIN_ACCOUNT) throw new Error('Gate not configured');
  config.nodes = [jsonRpcEndpoint(env)];
  config.timeout = 12000;
  const tx = new Transaction();
  await tx.addOperation('custom_json', {
    required_auths: [],
    required_posting_auths: [env.HIVE_MAIN_ACCOUNT],
    id: 'lite_account',
    json: JSON.stringify(buildRegistration(name, ownerPublic, postingPublic))
  });
  tx.sign(PrivateKey.from(env.GATE_POSTING_KEY));
  const result = await tx.broadcast() as {
    error?: unknown;
    result?: { tx_id?: string };
    id?: string;
  };
  if (result?.error) throw new Error('Hive rejected the registration transaction');
  // A successful broadcast may return a block reference instead of a tx id.
  return result?.result?.tx_id || result?.id || 'broadcast-submitted';
}
