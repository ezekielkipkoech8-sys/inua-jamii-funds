require('dotenv').config();
/* ============================================================
   Inua Jamii Funds — HashPay webhook receiver
   ------------------------------------------------------------
   - POST /webhook/hashpay : verifies X-Hashpay-Signature
     (HMAC-SHA256 of the RAW request body) and, on a valid
     payment.success event, appends the transaction to
     confirmed_payments.json.
   - GET  /webhook/status?reference=XXX : polls confirmed
     payments by reference for the client-side payment page.
   - GET  /health : health check.
   - GET  /  : serves index.html (homepage).
   ============================================================ */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// --- Config ---------------------------------------------------
const PORT = process.env.PORT || 3000;
// NOTE: real value goes in the .env / environment variables.
// This dev fallback is only so the server runs without setup.
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || process.env.HASHBACK_WEBHOOK_SECRET || 'dev-insecure-secret';

if (!process.env.WEBHOOK_SECRET && !process.env.HASHBACK_WEBHOOK_SECRET) {
  console.warn('WARNING: WEBHOOK_SECRET not set — using insecure dev fallback. Set HASHBACK_WEBHOOK_SECRET in .env for production.');
}

const DATA_FILE = path.join(__dirname, 'confirmed_payments.json');

const app = express();

// --- CORS -----------------------------------------------------
// Allow payment1.html (e.g. Live Server on 127.0.0.1:5500) to
// reach this API from a different origin during local dev.
app.use(cors());
// NOTE: no global express.json() — it would consume the raw request body
// before the /webhook/hashpay route's express.raw() parser, breaking the
// HMAC signature check (which must run over the exact raw bytes).

// --- Helpers --------------------------------------------------
function readPayments() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function writePayments(records) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(records, null, 2), 'utf8');
}

// Verify X-Hashpay-Signature = HMAC-SHA256(rawBody, secret)
function verifySignature(rawBody, signatureHeader) {
  if (!signatureHeader) return false;
  const expected = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');
  const given = String(signatureHeader).trim();
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(given, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// --- Routes ---------------------------------------------------

// Health check (moved off root so "/" can serve the homepage instead)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'inua-jamii-hashpay-webhook', time: new Date().toISOString() });
});

// Serve the static site (index.html, payment1.html, ...) as well. Needed on
// Vercel because the catch-all route forwards every request to server.js, so
// without this the HTML pages would 404.
app.use(express.static(path.join(__dirname)));

// Serve index.html at the root explicitly (in case express.static's default
// index resolution doesn't kick in under Vercel's catch-all routing).
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Webhook receiver — raw body needed for HMAC verification
app.post(
  '/webhook/hashpay',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const rawBody = req.body; // Buffer (raw)
    const signature = req.get('X-Hashpay-Signature');

    if (!verifySignature(rawBody, signature)) {
      return res.status(401).json({ error: 'invalid signature' });
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch (e) {
      return res.status(400).json({ error: 'invalid json body' });
    }

    // Only record successful payments
    const eventType = payload.event || payload.type || '';
    const success = payload.status === 'success' || eventType === 'payment.success';

    if (!success) {
      return res.status(200).json({ received: true, handled: false, note: 'non-success event ignored' });
    }

    const record = {
      transactionId: payload.transactionId || payload.data?.transactionId || '',
      receipt: payload.receipt || payload.data?.receipt || '',
      amount: payload.amount || payload.data?.amount || '',
      reference: payload.reference || payload.data?.reference || '',
      msisdn: payload.msisdn || payload.data?.msisdn || payload.phone || '',
      accountId: payload.accountId || payload.data?.accountId || payload.account || '',
      receivedAt: new Date().toISOString()
    };

    const payments = readPayments();
    payments.push(record);
    writePayments(payments);

    res.status(200).json({ received: true, handled: true });
  }
);

// Status polling endpoint used by payment1.html
app.get('/webhook/status', (req, res) => {
  const reference = String(req.query.reference || '').trim();
  if (!reference) {
    return res.status(400).json({ error: 'missing reference query param' });
  }

  const match = readPayments().find(p => p.reference === reference);

  if (match) {
    return res.json({ confirmed: true, ...match });
  }
  return res.json({ confirmed: false });
});

app.listen(PORT, () => {
  console.log(`Inua Jamii HashPay webhook listening on http://localhost:${PORT}`);
});