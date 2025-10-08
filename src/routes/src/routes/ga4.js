// src/routes/ga4.js
import express from 'express';
import fetch from 'node-fetch'; // ok com Node 20 + "type":"module"

const router = express.Router();

// ID de medição do seu GA4
const MEASUREMENT_ID = 'G-QRN64TGTNN';
// Segredo do Measurement Protocol (configure no Render como variável GA4_API_SECRET)
const API_SECRET = process.env.GA4_API_SECRET;

// (Opcional) Basic Auth reutilizando variáveis que você já usa
function requireBasicAuth(req, res, next) {
  const user = process.env.WEBHOOK_BASIC_USER;
  const pass = process.env.WEBHOOK_BASIC_PASS;
  if (!user || !pass) return next(); // se não configurou, segue sem auth

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

// POST /ga4/mp  → encaminha para o GA4 Measurement Protocol
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

    const url = `https://www.google-analytics.com/mp/collect?measurement_id=${MEASUREMENT_ID}&api_secret=${API_SECRET}`;

    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

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
