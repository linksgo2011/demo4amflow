async function feishuRequest({ method, url, userAccessToken, body }) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
  };
  if (userAccessToken) headers.authorization = `Bearer ${userAccessToken}`;

  const resp = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await resp.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    const err = new Error('ERR_FEISHU_API_NON_JSON');
    err.details = { status: resp.status, text };
    throw err;
  }

  if (!resp.ok) {
    const err = new Error('ERR_FEISHU_API_HTTP');
    err.details = { status: resp.status, body: json };
    throw err;
  }

  if (json && typeof json.code === 'number' && json.code !== 0) {
    const err = new Error('ERR_FEISHU_API_CODE');
    err.details = { code: json.code, msg: json.msg, body: json };
    throw err;
  }

  return json;
}

module.exports = {
  feishuRequest,
};

