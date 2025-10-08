import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';
import ga4Router from './routes/ga4.js';

const app = express();
app.use(express.json({ limit: '1mb' }));
// ==== Logs de requisições (simples, sem dependências) ====
const LOG_BODY = process.env.LOG_BODY === 'true'; // opcional: ativa log do body via var de ambiente

app.use((req, res, next) => {
  const start = Date.now();
  const ip =
    req.headers['x-forwarded-for'] ||
    req.socket?.remoteAddress ||
    '';

  res.on('finish', () => {
    const ms = Date.now() - start;
    // Log do corpo só para métodos que costumam ter payload
    const canLogBody = LOG_BODY && ['POST', 'PUT', 'PATCH'].includes(req.method);
    const bodySnippet = canLogBody ? ` body=${JSON.stringify(req.body).slice(0, 1000)}` : '';

    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ` +
      `${res.statusCode} ${ms}ms ip=${ip}${bodySnippet}`
    );
  });

  next();
});
// === Rotas ===
app.use('/ga4', ga4Router);   // -> isto habilita POST https://.../ga4/mp
app.get('/health', (req, res) => res.json({ ok: true }));
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`TeclaBet CAPI server running on port ${PORT}`);
});


const PIXEL_ID = process.env.META_PIXEL_ID;
const ACCESS_TOKEN = process.env.META_CAPI_TOKEN;
const GRAPH_VERSION = process.env.GRAPH_VERSION || 'v21.0';
const WEBHOOK_USER = process.env.WEBHOOK_BASIC_USER;
const WEBHOOK_PASS = process.env.WEBHOOK_BASIC_PASS;
const TEST_EVENT_CODE = process.env.TEST_EVENT_CODE || '';

const DB_FILE = path.join(process.cwd(), 'db.json');
function loadDB(){ try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { sessions:{}, users:{} }; } }
function saveDB(db){ fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
const db = loadDB();

function sha256(s){ if(!s) return null; return crypto.createHash('sha256').update(String(s).trim().toLowerCase()).digest('hex'); }

function basicAuth(req, res, next){
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Basic ')) return res.status(401).send('Unauthorized');
  const decoded = Buffer.from(auth.replace('Basic ', ''), 'base64').toString('utf8');
  const [u, p] = decoded.split(':');
  if (u === WEBHOOK_USER && p === WEBHOOK_PASS) return next();
  return res.status(401).send('Unauthorized');
}

async function sendCapiEvent({ event_name, event_time, event_id, event_source_url, user, client, custom }){
  const user_data = {};
  if (user?.email) user_data.em = sha256(user.email);
  if (user?.phone) user_data.ph = sha256(user.phone);
  if (user?.external_id) user_data.external_id = sha256(user.external_id);
  if (client?.fbp) user_data.fbp = client.fbp;
  if (client?.fbc) user_data.fbc = client.fbc;
  if (client?.ip) user_data.client_ip_address = client.ip;
  if (client?.ua) user_data.client_user_agent = client.ua;

  const body = {
    data: [{
      event_name,
      event_time: Math.floor((event_time || Date.now()) / 1000),
      action_source: "website",
      event_id,
      event_source_url: event_source_url || undefined,
      user_data,
      custom_data: custom || {}
    }]
  };
  if (TEST_EVENT_CODE) body['test_event_code'] = TEST_EVENT_CODE;

  const url = `https://graph.facebook.com/${GRAPH_VERSION}/${PIXEL_ID}/events?access_token=${ACCESS_TOKEN}`;
  const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  const json = await res.json();
  if (!res.ok || json.error) { throw new Error(`Meta CAPI error: ${res.status} ${JSON.stringify(json)}`); }
  return json;
}

// mini “banco” local
function upsertSession(order_id, data){ db.sessions[order_id] = { ...(db.sessions[order_id]||{}), ...data, updated_at: Date.now() }; saveDB(db); return db.sessions[order_id]; }
function getSession(order_id){ return db.sessions[order_id]; }
function markPaid(user_id){ if (!db.users[user_id]) db.users[user_id] = { paid_count: 0 }; db.users[user_id].paid_count += 1; saveDB(db); }
function isFTD(user_id){ const c = db.users[user_id]?.paid_count || 0; return c === 0; }

// saúde
app.get('/health', (req,res) => res.json({ ok: true }));

// endpoint para anexar fbp/fbc do front se desejar
app.post('/meta/attach', express.json(), (req,res) => {
  const { order_id, user_id, email, phone, fbp, fbc, event_source_url, user_agent } = req.body || {};
  if (!order_id) return res.status(400).json({ error: 'order_id required' });
  const s = upsertSession(order_id, { user_id, email, phone, fbp, fbc, event_source_url, ua: user_agent });
  res.json({ ok: true, session: s });
});

// === WEBHOOK: USUÁRIO CRIADO (Cadastro) ===
app.all(['/webhooks/user_created', '/webhooks/user_created/'], basicAuth, async (req,res) => {
  // plataformas fazem GET/HEAD de verificação — responda 200
  if (req.method !== 'POST') return res.status(200).send('OK');
  try{
    const p = req.body || {};
    const user_id = String(p.user_id || p.id || '');
    await sendCapiEvent({
      event_name: 'CompleteRegistration',
      event_id: user_id || undefined,
      user: { external_id: user_id, email: p.email, phone: p.phone },
      client: {},
      custom: {}
    });
    res.sendStatus(200);
  }catch(e){ console.error(e); res.status(500).json({ error: String(e) }); }
});

// === WEBHOOK: DEPÓSITO CRIADO (Pix gerado) ===
app.all(['/webhooks/deposit_created', '/webhooks/deposit_created/'], basicAuth, async (req,res) => {
  if (req.method !== 'POST') return res.status(200).send('OK');
  try{
    const p = req.body || {};
    const order_id = String(p.gateway_transaction_id || p.deposit_id || '');
    const user_id = String(p.user_id || '');
    const amount = Number(p.amount || 0);

    upsertSession(order_id, { user_id, email: p.user_email, phone: p.user_phone, value: amount });

    await sendCapiEvent({
      event_name: 'AddPaymentInfo',
      event_id: order_id,
      user: { external_id: user_id, email: p.user_email, phone: p.user_phone },
      client: {},
      custom: { currency:'BRL', value: Number.isFinite(amount)? amount: undefined, order_id, payment_method:'PIX' }
    });

    res.sendStatus(200);
  }catch(e){ console.error(e); res.status(500).json({ error: String(e) }); }
});

// === WEBHOOK: DEPÓSITO PAGO (FTD/Repeat) ===
app.all(['/webhooks/deposit_paid', '/webhooks/deposit_paid/'], basicAuth, async (req,res) => {
  if (req.method !== 'POST') return res.status(200).send('OK');
  try{
    const p = req.body || {};
    const order_id = String(p.gateway_transaction_id || p.deposit_id || '');
    const user_id = String(p.user_id || '');
    const amount = Number(p.amount || 0);

    const s = getSession(order_id) || {};
    const ftd = isFTD(user_id);

    await sendCapiEvent({
      event_name: 'Purchase',
      event_id: order_id,
      event_source_url: s.event_source_url || undefined,
      user: { external_id: user_id, email: s.email || p.user_email, phone: s.phone || p.user_phone },
      client: { fbp: s.fbp, fbc: s.fbc, ua: s.ua },
      custom: { currency:'BRL', value: Number.isFinite(amount)? amount: undefined, order_id, content_name:'Pix Deposit', content_category: ftd ? 'FTD' : 'Repeat' }
    });

    markPaid(user_id);
    res.sendStatus(200);
  }catch(e){ console.error(e); res.status(500).json({ error: String(e) }); }
});

// erro genérico
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: String(err) }); });

app.listen(PORT, () => console.log(`TeclaBet CAPI server running on port ${PORT}`));
