const crypto = require('node:crypto');

function base64UrlEncodeBuffer(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlEncodeString(s) {
  return base64UrlEncodeBuffer(Buffer.from(String(s), 'utf8'));
}

function base64UrlDecodeToBuffer(b64url) {
  const s = String(b64url || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s + pad, 'base64');
}

function signToken(token, secret) {
  if (!secret) throw new Error('ERR_MISSING_TOKEN_COOKIE_SECRET');
  const payload = base64UrlEncodeString(token);
  const sig = crypto.createHmac('sha256', secret).update(payload).digest();
  return `${payload}.${base64UrlEncodeBuffer(sig)}`;
}

function verifyTokenCookie(value, secret) {
  if (!value) return { ok: false, error: 'ERR_MISSING_TOKEN_COOKIE' };
  if (!secret) return { ok: false, error: 'ERR_MISSING_TOKEN_COOKIE_SECRET' };
  const parts = String(value).split('.');
  if (parts.length !== 2) return { ok: false, error: 'ERR_INVALID_TOKEN_COOKIE_FORMAT' };
  const [payload, sigB64] = parts;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest();
  const got = base64UrlDecodeToBuffer(sigB64);
  if (got.length !== expected.length) return { ok: false, error: 'ERR_INVALID_TOKEN_COOKIE_SIGNATURE' };
  if (!crypto.timingSafeEqual(got, expected)) return { ok: false, error: 'ERR_INVALID_TOKEN_COOKIE_SIGNATURE' };
  const token = base64UrlDecodeToBuffer(payload).toString('utf8');
  return { ok: true, token };
}

function getCookie(req, name) {
  const header = req.headers?.cookie || '';
  const pairs = header.split(';');
  for (const p of pairs) {
    const s = p.trim();
    if (!s) continue;
    const idx = s.indexOf('=');
    if (idx === -1) continue;
    const k = s.slice(0, idx).trim();
    const v = s.slice(idx + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

module.exports = {
  signToken,
  verifyTokenCookie,
  getCookie,
};

