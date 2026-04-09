const crypto = require('node:crypto');

function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecodeToBuffer(b64url) {
  const s = String(b64url || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s + pad, 'base64');
}

function signState(payload, secret, ttlSeconds = 300) {
  if (!secret) throw new Error('ERR_MISSING_STATE_SECRET');
  const now = Math.floor(Date.now() / 1000);
  const body = {
    ...payload,
    iat: now,
    exp: now + ttlSeconds,
  };
  const payloadB64 = base64UrlEncode(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  const sigB64 = base64UrlEncode(sig);
  return `${payloadB64}.${sigB64}`;
}

function verifyState(token, secret) {
  if (!token) return { ok: false, error: 'ERR_MISSING_STATE' };
  if (!secret) return { ok: false, error: 'ERR_MISSING_STATE_SECRET' };

  const parts = String(token).split('.');
  if (parts.length !== 2) return { ok: false, error: 'ERR_INVALID_STATE_FORMAT' };
  const [payloadB64, sigB64] = parts;

  const expectedSig = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  const gotSig = base64UrlDecodeToBuffer(sigB64);
  if (gotSig.length !== expectedSig.length) return { ok: false, error: 'ERR_INVALID_STATE_SIGNATURE' };
  if (!crypto.timingSafeEqual(gotSig, expectedSig)) return { ok: false, error: 'ERR_INVALID_STATE_SIGNATURE' };

  let payload;
  try {
    payload = JSON.parse(base64UrlDecodeToBuffer(payloadB64).toString('utf8'));
  } catch {
    return { ok: false, error: 'ERR_INVALID_STATE_PAYLOAD' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && now > payload.exp) {
    return { ok: false, error: 'ERR_STATE_EXPIRED' };
  }

  return { ok: true, payload };
}

module.exports = {
  signState,
  verifyState,
};

