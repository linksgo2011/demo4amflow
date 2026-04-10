const { randomUUID } = require('node:crypto');

function truncate(value, maxLen) {
  const s = String(value ?? '');
  if (s.length <= maxLen) return s;
  return `${s.slice(0, maxLen)}…(${s.length})`;
}

function redactHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const key = String(k).toLowerCase();
    if (key === 'authorization' || key === 'cookie' || key === 'set-cookie') {
      out[key] = '[REDACTED]';
      continue;
    }
    out[key] = Array.isArray(v) ? v.map((x) => truncate(x, 500)) : truncate(v, 500);
  }
  return out;
}

function safeCloneBody(body, maxLen = 8000) {
  if (!body) return null;
  try {
    const raw = JSON.stringify(body);
    return JSON.parse(truncate(raw, maxLen));
  } catch {
    return truncate(String(body), maxLen);
  }
}

function createRequestLog({ max = 200 } = {}) {
  const items = [];

  function push(entry) {
    items.unshift(entry);
    if (items.length > max) items.length = max;
  }

  function pushEvent(event, data) {
    push({
      id: randomUUID(),
      ts: new Date().toISOString(),
      event,
      data: data || null,
    });
  }

  function list() {
    return items.slice();
  }

  function clear() {
    items.length = 0;
  }

  function middleware(req, _res, next) {
    const entry = {
      id: randomUUID(),
      ts: new Date().toISOString(),
      method: req.method,
      path: req.path,
      originalUrl: req.originalUrl,
      ip: req.ip,
      headers: redactHeaders(req.headers),
      query: req.query || null,
      body: safeCloneBody(req.body),
    };
    push(entry);
    next();
  }

  return { middleware, list, clear, pushEvent };
}

module.exports = { createRequestLog };
