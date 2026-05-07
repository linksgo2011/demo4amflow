let cached = null;

function isStdoutEnabled() {
  const v = String(process.env.DEBUG_FEISHU_HTTP || '').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

async function getTenantAccessToken({ clientId, clientSecret, requestLog }) {
  if (!clientId || !clientSecret) {
    const err = new Error('ERR_MISSING_FEISHU_APP_CREDENTIALS');
    err.details = { need: ['FEISHU_CLIENT_ID', 'FEISHU_CLIENT_SECRET'] };
    throw err;
  }

  const now = Date.now();
  if (cached && cached.expiresAtMs && now + 5 * 60 * 1000 < cached.expiresAtMs) {
    return cached.tenantAccessToken;
  }

  const url = 'https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal';
  if (requestLog) {
    requestLog.pushEvent('feishu.http.request', {
      method: 'POST',
      url,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: { app_id: clientId, app_secret: '***' },
    });
  }
  if (isStdoutEnabled()) {
    console.log(
      '[feishu-http] request',
      JSON.stringify({
        method: 'POST',
        url,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: { app_id: clientId, app_secret: '***' },
      }),
    );
  }

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      app_id: clientId,
      app_secret: clientSecret,
    }),
  });

  const text = await resp.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    const err = new Error('ERR_FEISHU_APP_TOKEN_NON_JSON');
    err.details = { status: resp.status, text: String(text).slice(0, 8000) };
    if (requestLog) {
      requestLog.pushEvent('feishu.http.response', {
        method: 'POST',
        url,
        status: resp.status,
        contentType: resp.headers.get('content-type') || null,
        bodyText: String(text).slice(0, 8000),
      });
    }
    if (isStdoutEnabled()) {
      console.log(
        '[feishu-http] response',
        JSON.stringify({
          method: 'POST',
          url,
          status: resp.status,
          contentType: resp.headers.get('content-type') || null,
          bodyText: String(text).slice(0, 8000),
        }),
      );
    }
    throw err;
  }

  if (!resp.ok) {
    const err = new Error('ERR_FEISHU_APP_TOKEN_HTTP');
    err.details = { status: resp.status, body: json };
    if (requestLog) {
      requestLog.pushEvent('feishu.http.response', {
        method: 'POST',
        url,
        status: resp.status,
        contentType: resp.headers.get('content-type') || null,
        body: json,
      });
    }
    if (isStdoutEnabled()) {
      console.log(
        '[feishu-http] response',
        JSON.stringify({
          method: 'POST',
          url,
          status: resp.status,
          contentType: resp.headers.get('content-type') || null,
          body: json,
        }),
      );
    }
    throw err;
  }

  if (json && typeof json.code === 'number' && json.code !== 0) {
    const err = new Error('ERR_FEISHU_APP_TOKEN_CODE');
    err.details = { code: json.code, msg: json.msg, body: json };
    if (requestLog) {
      requestLog.pushEvent('feishu.http.response', {
        method: 'POST',
        url,
        status: resp.status,
        contentType: resp.headers.get('content-type') || null,
        body: json,
      });
    }
    if (isStdoutEnabled()) {
      console.log(
        '[feishu-http] response',
        JSON.stringify({
          method: 'POST',
          url,
          status: resp.status,
          contentType: resp.headers.get('content-type') || null,
          body: json,
        }),
      );
    }
    throw err;
  }

  if (requestLog) {
    requestLog.pushEvent('feishu.http.response', {
      method: 'POST',
      url,
      status: resp.status,
      contentType: resp.headers.get('content-type') || null,
      body: { ...json, app_access_token: json.app_access_token ? '***' : undefined, tenant_access_token: json.tenant_access_token ? '***' : undefined },
    });
  }
  if (isStdoutEnabled()) {
    console.log(
      '[feishu-http] response',
      JSON.stringify({
        method: 'POST',
        url,
        status: resp.status,
        contentType: resp.headers.get('content-type') || null,
        body: {
          ...json,
          app_access_token: json.app_access_token ? '***' : undefined,
          tenant_access_token: json.tenant_access_token ? '***' : undefined,
        },
      }),
    );
  }

  const tenantAccessToken = json.tenant_access_token || json.app_access_token || null;
  const expireSeconds = Number(json.expire || 0);
  if (!tenantAccessToken || !expireSeconds) {
    const err = new Error('ERR_FEISHU_APP_TOKEN_MISSING_FIELDS');
    err.details = { body: json };
    throw err;
  }

  cached = {
    tenantAccessToken,
    expiresAtMs: now + expireSeconds * 1000,
  };

  return tenantAccessToken;
}

module.exports = {
  getTenantAccessToken,
};
