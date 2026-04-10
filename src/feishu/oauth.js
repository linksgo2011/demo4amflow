function buildAuthorizeUrl({ clientId, redirectUri, scope, state }) {
  const url = new URL('https://accounts.feishu.cn/open-apis/authen/v1/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', redirectUri);
  if (scope) url.searchParams.set('scope', scope);
  if (state) url.searchParams.set('state', state);
  return url.toString();
}

async function exchangeCodeForToken({ clientId, clientSecret, code, redirectUri }) {
  const url = 'https://open.feishu.cn/open-apis/authen/v2/oauth/token';
  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('client_id', clientId);
  body.set('client_secret', clientSecret);
  body.set('redirect_uri', redirectUri);

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  const text = await resp.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    const err = new Error('ERR_FEISHU_TOKEN_NON_JSON');
    err.details = { status: resp.status, text };
    throw err;
  }

  if (!resp.ok) {
    const err = new Error('ERR_FEISHU_TOKEN_HTTP');
    err.details = { status: resp.status, body: json };
    throw err;
  }

  return json;
}

module.exports = {
  buildAuthorizeUrl,
  exchangeCodeForToken,
};

