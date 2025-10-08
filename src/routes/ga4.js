// src/routes/ga4.js
import express from 'express';
import fetch from 'node-fetch'; // ok com Node 20 + "type":"module"

const router = express.Router();

// ID de medição do seu GA4 (pode deixar fixo ou mover para .env se preferir)
const MEASUREMENT_ID = 'G-QRN64TGTNN';
// Segredo do Measurement Protocol (configure no Render como GA4_API_SECRET)
const API_SECRET = process.env.GA4_API_SECRET;

// (Opcional) Basic Auth reaproveitando as mesmas variáveis dos webhooks
function requireBasicAuth(req, res, next) {
  const user = process.env.WEBHOOK_BASIC_USER;
  const pass = process.env.WEBHOOK_BASIC_PASS;
  if (!user || !pass) return next(); // sem credenciais, segue sem auth

  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="ga4"');
    return res.status(401).json({ error: 'unauthorized' });
  }
  const token = header.split(' ')[1] || '';
  const decoded = Buffer.from(token, 'base64').toString('utf8');
  const [u, p] = decoded.split(':');
  if (u === user && p === pass) return next();

  res.set('WWW-Authenticate', 'Basic realm="ga4"');
  return res.status(401).json({ error: 'unauthorized' });
}

// Helper: detecta se há debug_mode em algum evento do payload
function hasDebugMode(payload) {
  try {
    if (!payload?.events?.length) return false;
    return payload.events.some(ev => {
      const v = ev?.params?.debug_mode;
      return v === 1 || v === true || v === '1';
    });
  } catch {
    return false;
  }
}

// POST /ga4/mp → repassa o payload para o GA4 Measurement Protocol
router.post('/mp', requireBasicAuth, async (req, res) => {
  try {
    const payload = req.body;

    // validações mínimas
    if (!payload || (!payload.client_id && !payload.user_id)) {
      return res.status(400).json({ error: 'client_id ou user_id é obrigatório' });
    }
    if (!Array.isArray(payload.events) || payload.events.length === 0) {
      return res.status(400).json({ error: 'events[] é obrigatório' });
    }
    if (!API_SECRET) {
      return res.status(500).json({ error: 'GA4_API_SECRET não configurado' });
    }

    // Usa /debug/mp/collect quando vier debug_mode, senão /mp/collect normal
    const base = hasDebugMode(payload)
      ? 'https://www.google-analytics.com/debug/mp/collect'
      : 'https://www.google-analytics.com/mp/collect';

    const url = `${base}?measurement_id=${MEASUREMENT_ID}&api_secret=${API_SECRET}`;

    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    // No endpoint de debug o GA4 retorna JSON com validationMessages
    if (hasDebugMode(payload)) {
      const text = await r.text();
      // tenta converter para JSON, senão devolve texto
      try {
        const json = JSON.parse(text || '{}');
        if (!r.ok) {
          return res.status(r.status).json({ error: 'GA4 debug error', details: json });
        }
        return res.status(200).json(json);
      } catch {
        if (!r.ok) {
          return res.status(r.status).send(text || 'GA4 debug error');
        }
        return res.status(200).send(text || '{}');
      }
    }

    // /mp/collect normal retorna 204 em caso de sucesso
    if (!r.ok) {
      const text = await r.text();
      return res.status(r.status).json({ error: 'GA4 MP error', details: text });
    }
    return res.status(204).send(); // sucesso sem corpo
  } catch (e) {
    return res.status(500).json({ error: 'internal_error', details: e.message });
  }
});

export default router;
