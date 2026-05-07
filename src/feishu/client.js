function redactHeaderValue(name, value) {
  const key = String(name || '').toLowerCase();
  if (key === 'authorization') return 'Bearer ***';
  return value;
}

function safeJson(obj) {
  try {
    return JSON.parse(JSON.stringify(obj));
  } catch {
    return null;
  }
}

function isStdoutEnabled() {
  const v = String(process.env.DEBUG_FEISHU_HTTP || '').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

async function feishuRequest({ method, url, userAccessToken, body, requestLog }) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
  };
  if (userAccessToken) headers.authorization = `Bearer ${userAccessToken}`;

  const reqLog = {
    method,
    url,
    headers: Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k, redactHeaderValue(k, v)]),
    ),
    body: safeJson(body),
  };

  if (requestLog) {
    requestLog.pushEvent('feishu.http.request', reqLog);
  }
  if (isStdoutEnabled()) {
    console.log('[feishu-http] request', JSON.stringify(reqLog));
  }

  const resp = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await resp.text();
  const contentType = resp.headers.get('content-type') || null;
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    const err = new Error('ERR_FEISHU_API_NON_JSON');
    err.details = { status: resp.status, text: String(text).slice(0, 8000) };
    const resLog = {
      method,
      url,
      status: resp.status,
      contentType,
      bodyText: String(text).slice(0, 8000),
    };
    if (requestLog) requestLog.pushEvent('feishu.http.response', resLog);
    if (isStdoutEnabled()) console.log('[feishu-http] response', JSON.stringify(resLog));
    throw err;
  }

  if (!resp.ok) {
    const err = new Error('ERR_FEISHU_API_HTTP');
    err.details = { status: resp.status, body: json };
    const resLog = {
      method,
      url,
      status: resp.status,
      contentType,
      body: json,
    };
    if (requestLog) requestLog.pushEvent('feishu.http.response', resLog);
    if (isStdoutEnabled()) console.log('[feishu-http] response', JSON.stringify(resLog));
    throw err;
  }

  if (json && typeof json.code === 'number' && json.code !== 0) {
    const err = new Error('ERR_FEISHU_API_CODE');
    err.details = { code: json.code, msg: json.msg, body: json };
    const resLog = {
      method,
      url,
      status: resp.status,
      contentType,
      body: json,
    };
    if (requestLog) requestLog.pushEvent('feishu.http.response', resLog);
    if (isStdoutEnabled()) console.log('[feishu-http] response', JSON.stringify(resLog));
    throw err;
  }

  const resLog = {
    method,
    url,
    status: resp.status,
    contentType,
    body: json,
  };
  if (requestLog) requestLog.pushEvent('feishu.http.response', resLog);
  if (isStdoutEnabled()) console.log('[feishu-http] response', JSON.stringify(resLog));

  return json;
}

module.exports = {
  feishuRequest,
};
