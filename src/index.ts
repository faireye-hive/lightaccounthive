import { Transaction, PrivateKey, config } from 'hive-tx';

export interface Env {
  HIVE_MAIN_ACCOUNT: string;
  SERVER_ACTIVE_KEY: string;
  SERVER_POSTING_KEY: string;
  HIVE_NODE?: string;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Configuração baseada na documentação v7 do hive-tx
const DEFAULT_NODE = 'https://api.hive.blog';
config.nodes = [DEFAULT_NODE, 'https://api.deathwing.me'];
config.timeout = 10000;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === '/register' && request.method === 'POST') {
        return await handleRegister(request, env);
      }

      if (url.pathname === '/sign-and-broadcast' && request.method === 'POST') {
        return await handleSignAndBroadcast(request, env);
      }

      if (url.pathname === '/find-account' && request.method === 'GET') {
        return await handleFindAccount(request, env);
      }

      if (url.pathname === '/main-accounts' && request.method === 'GET') {
        return jsonResponse({ mainAccounts: [env.HIVE_MAIN_ACCOUNT] });
      }

      return jsonResponse({ error: 'Rota não encontrada' }, 404);
    } catch (err: any) {
      console.error(err);
      return jsonResponse({ error: err.message || 'Erro interno no servidor' }, 500);
    }
  },
};

/**
 * Utilitário leve de JSON-RPC via fetch nativo para buscas
 */
async function hiveRpcCall(nodeUrl: string, method: string, params: any): Promise<any> {
  const res = await fetch(nodeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method,
      params,
      id: 1,
    }),
  });
  return await res.json();
}

/**
 * ROTA 1: Registrar nova chave de postagem Light na conta do servidor
 */
/**
 * ROTA 1: Registrar nova chave de postagem Light na conta do servidor com Nickname
 */
async function handleRegister(request: Request, env: Env): Promise<Response> {
  const body = (await request.json()) as { publicLightKey: string; nickname?: string };
  const { publicLightKey, nickname } = body;

  if (!publicLightKey) {
    return jsonResponse({ error: 'publicLightKey é obrigatória' }, 400);
  }

  // Define um nickname padrão caso o usuário não envie um
  const finalNickname = nickname || `Light_${publicLightKey.slice(0, 8)}`;

  const nodeUrl = env.HIVE_NODE || DEFAULT_NODE;

  // 1. Busca dados da conta via JSON-RPC nativo
  const accountRes = await hiveRpcCall(nodeUrl, 'condenser_api.get_accounts', [[env.HIVE_MAIN_ACCOUNT]]);
  if (!accountRes || !accountRes.result || accountRes.result.length === 0) {
    return jsonResponse({ error: 'Conta principal não encontrada no Hive' }, 404);
  }

  const account = accountRes.result[0];
  const postingAuth = account.posting;

  // 2. Lidar com o posting_json_metadata
  let postingJson: any = {};
  try {
    if (account.posting_json_metadata) {
      postingJson = JSON.parse(account.posting_json_metadata);
    }
  } catch (e) {
    // Se falhar no parse, continua com o objeto vazio
  }

  // Garante que o objeto light_accounts exista
  if (!postingJson.light_accounts) {
    postingJson.light_accounts = {};
  }

  // 3. Verificar se a chave já existe e atualizar a authority se necessário
  const keyExists = postingAuth.key_auths.some(([key]: [string, number]) => key === publicLightKey);

  // Se a chave não existe na authority, nós a adicionamos e reordenamos
  if (!keyExists) {
    postingAuth.key_auths.push([publicLightKey, 1]);
    postingAuth.key_auths.sort((a: [string, number], b: [string, number]) => a[0].localeCompare(b[0]));
  }

  // Verifica se a chave já existe e se o nickname é o mesmo (evita transações desnecessárias)
  if (keyExists && postingJson.light_accounts[publicLightKey] === finalNickname) {
    return jsonResponse({ message: 'Chave já registrada na conta com este nickname' }, 200);
  }

  // Adiciona/Atualiza o nickname no json
  postingJson.light_accounts[publicLightKey] = finalNickname;

  // 4. Criar transação usando account_update2
  const tx = new Transaction();
  await tx.addOperation('account_update2', {
    account: env.HIVE_MAIN_ACCOUNT,
    posting: postingAuth,
    memo_key: account.memo_key,
    json_metadata: account.json_metadata || "", // Mantém o metadata antigo intacto
    posting_json_metadata: JSON.stringify(postingJson),
    extensions: []
  });

  // 5. Assinar (requer chave ativa para mudar a authority) e Transmitir
  const serverPrivateKey = PrivateKey.from(env.SERVER_ACTIVE_KEY);
  tx.sign(serverPrivateKey);

  const result = await tx.broadcast();

  if (result && result.error) {
    return jsonResponse({ error: result.error }, 500);
  }

  return jsonResponse({
    success: true,
    txId: result?.result?.tx_id || result?.id,
    message: 'Chave Light e Nickname registrados com sucesso!',
    nickname: finalNickname
  });
}

/**
 * ROTA 2: Validar, assinar via Multisig e transmitir transação
 */
async function handleSignAndBroadcast(request: Request, env: Env): Promise<Response> {
  const body = (await request.json()) as {
    tx: any; // Este 'tx' é o objeto cru contendo ref_block_num, operations, etc.
    signatureLight: string;
    publicLightKey: string;
  };

  const { tx: rawTx, signatureLight, publicLightKey } = body;

  if (!rawTx || !signatureLight || !publicLightKey) {
    return jsonResponse({ error: 'tx, signatureLight e publicLightKey são obrigatórios' }, 400);
  }

// Garante que o objeto tenha a estrutura interna padrão do hive-tx (envelopado em .transaction)
  const txObj = rawTx.transaction ? rawTx.transaction : rawTx;
  const tx = new Transaction(txObj);

  // Assegura que a propriedade interna exista para o loop ler com segurança
  if (!tx.transaction) {
    tx.transaction = txObj;
  }

  // 1. Regras de Isolamento de Escopo (Proteção)
  const keyPrefix = await getKeyPrefix(publicLightKey);

  // Na v7 o objeto 'transaction' pode vir como 'undefined' no typechecking, por isso usamos '!'
  for (const op of tx.transaction!.operations) {
    const [opName, opData] = op;

    if (opName === 'comment') {
      if (opData.author !== env.HIVE_MAIN_ACCOUNT) {
        return jsonResponse({ error: 'O autor da operação deve ser a conta do sistema' }, 403);
      }

      if (!opData.permlink.startsWith(`u-${keyPrefix}-`)) {
        return jsonResponse(
          {
            error: `Acesso negado: o permlink deve começar com 'u-${keyPrefix}-' para garantir a autoria.`,
          },
          403
        );
      }
    } else if (opName === 'comment_options') {
      if (opData.author !== env.HIVE_MAIN_ACCOUNT) {
        return jsonResponse({ error: 'O autor da opção deve ser a conta do sistema' }, 403);
      }

      if (!opData.permlink.startsWith(`u-${keyPrefix}-`)) {
        return jsonResponse(
          {
            error: `Acesso negado: o permlink das opções deve começar com 'u-${keyPrefix}-'.`,
          },
          403
        );
      }
    } else if (opName === 'vote') {
      if (opData.voter !== env.HIVE_MAIN_ACCOUNT) {
        return jsonResponse({ error: 'Votante inválido' }, 403);
      }
    } else if (opName === 'custom_json') {
      if (!opData.required_posting_auths.includes(env.HIVE_MAIN_ACCOUNT)) {
        return jsonResponse({ error: 'Chave de postagem da conta principal necessária' }, 403);
      }
    } else {
      return jsonResponse({ error: `Operação do tipo '${opName}' não é permitida para contas Light` }, 403);
    }
  }

  // 2. Anexar a assinatura do cliente (Light)
  tx.transaction!.signatures = tx.transaction!.signatures || [];
  if (!tx.transaction!.signatures.includes(signatureLight)) {
    tx.transaction!.signatures.push(signatureLight);
  }

  // Anexar assinatura do Servidor
  const serverPrivateKey = PrivateKey.from(env.SERVER_POSTING_KEY);
  tx.sign(serverPrivateKey);

  // 3. Transmitir transação combinada
  const result = await tx.broadcast();

  if (result && result.error) {
    return jsonResponse({ error: result.error }, 500);
  }

  return jsonResponse({
    success: true,
    txId: result?.result?.tx_id || result?.id,
    blockNum: result?.result?.block_num || result?.block_num,
  });
}

/**
 * ROTA 3: Descobrir qual conta principal gerencia uma determinada pubkey Light
 */
async function handleFindAccount(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const publicLightKey = url.searchParams.get('pubkey');

  if (!publicLightKey) {
    return jsonResponse({ error: "Parâmetro 'pubkey' é obrigatório na query string" }, 400);
  }

  // Aqui você define quais são as suas contas principais de infraestrutura.
  // No futuro, se criar a conta2, basta adicionar aqui: ['accountcreatorx', 'accountcreator_2', ...]
  const mainAccounts = [env.HIVE_MAIN_ACCOUNT];
  // Exemplo se tiver mais de uma fixa ou se quiser puxar de uma env em JSON:
  // const mainAccounts = env.ALL_MAIN_ACCOUNTS ? JSON.parse(env.ALL_MAIN_ACCOUNTS) : [env.HIVE_MAIN_ACCOUNT];

  const nodeUrl = env.HIVE_NODE || DEFAULT_NODE;

  // Busca os dados de todas as contas principais em paralelo
  const rpcPayload = mainAccounts.map((acc, index) => ({
    jsonrpc: '2.0',
    method: 'condenser_api.get_accounts',
    params: [[acc]],
    id: index + 1
  }));

  const res = await fetch(nodeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(rpcPayload),
  });

  const results = await res.json();
  const responses = Array.isArray(results) ? results : [results];

  for (const resp of responses) {
    if (resp && resp.result && resp.result.length > 0) {
      const account = resp.result[0];
      const accountName = account.name;

      // Verifica no posting_json_metadata se a chave existe em light_accounts
      try {
        if (account.posting_json_metadata) {
          const postingJson = JSON.parse(account.posting_json_metadata);
          if (postingJson.light_accounts && postingJson.light_accounts[publicLightKey]) {
            return jsonResponse({
              found: true,
              mainAccount: accountName,
              nickname: postingJson.light_accounts[publicLightKey]
            });
          }
        }
      } catch (e) {
        // Ignora erros de parse e continua buscando nas outras contas
      }
    }
  }

  return jsonResponse({
    found: false,
    message: 'Chave Light não encontrada em nenhuma conta principal do sistema.'
  }, 404);
}

/**
 * Utilitário SHA256 usando Web Crypto API nativa do Cloudflare Worker
 */
async function getKeyPrefix(pubKey: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(pubKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 10);
}

function jsonResponse(data: object, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
    },
  });
}
