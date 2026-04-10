const { buildAuthorizeUrl, exchangeCodeForToken } = require('./oauth');

function registerChatRoutes({
  app,
  config,
  resolveBaseUrlFromReq,
  sessionSecret,
  signState,
  verifyState,
  requestLog,
}) {
  app.get('/chat', (req, res) => {
    const baseUrl = config.baseUrl || resolveBaseUrlFromReq(req);
    const redirectUri = `${baseUrl}/chat/callback`;
    const hasToken = Boolean(req.session?.feishu?.userAccessToken);
    res.type('text/html');
    if (hasToken) {
      return res.render('feishu-chat-room', {
        baseUrl,
        chatId: config.feishuChatId,
        tokenPreview: String(req.session?.feishu?.userAccessToken || '').slice(0, 12),
      });
    }
    res.render('feishu-chat', {
      baseUrl,
      redirectUri,
      hasCreds: Boolean(config.feishuClientId && config.feishuClientSecret),
      scope: config.feishuScope || '',
    });
  });

  app.get('/chat/login', (req, res) => {
    const baseUrl = config.baseUrl || resolveBaseUrlFromReq(req);
    const redirectUri = `${baseUrl}/chat/callback`;

    if (!config.feishuClientId || !config.feishuClientSecret) {
      res.status(400);
      return res.render('error', {
        title: '缺少飞书配置',
        message: '请先配置 FEISHU_CLIENT_ID 与 FEISHU_CLIENT_SECRET。',
      });
    }

    const state = signState(
      {
        redirectUri,
        at: Date.now(),
      },
      sessionSecret,
      10 * 60,
    );

    const authorizeUrl = buildAuthorizeUrl({
      clientId: config.feishuClientId,
      redirectUri,
      scope: config.feishuScope || null,
      state,
    });

    return res.redirect(authorizeUrl);
  });

  app.get('/chat/logout', (req, res) => {
    if (req.session) req.session.feishu = null;
    res.redirect('/chat');
  });

  app.post('/chat/token', (req, res) => {
    const token = String(req.body?.userAccessToken || '').trim();
    if (!token) {
      res.status(400);
      return res.render('error', { title: '参数错误', message: 'userAccessToken 不能为空' });
    }
    req.session.feishu = { userAccessToken: token, setAt: new Date().toISOString() };
    if (requestLog) requestLog.pushEvent('feishu.token.set', { by: 'manual' });
    res.redirect('/chat');
  });

  app.get('/chat/callback', async (req, res) => {
    const baseUrl = config.baseUrl || resolveBaseUrlFromReq(req);
    const fallbackRedirectUri = `${baseUrl}/chat/callback`;

    const code = req.query?.code ? String(req.query.code) : null;
    const state = req.query?.state ? String(req.query.state) : null;

    if (!config.feishuClientId || !config.feishuClientSecret) {
      res.status(400);
      return res.render('error', {
        title: '缺少飞书配置',
        message: '请先配置 FEISHU_CLIENT_ID 与 FEISHU_CLIENT_SECRET。',
      });
    }

    if (!code) {
      res.status(400);
      return res.render('error', {
        title: '回调缺少 code',
        message: `query.code 为空。query=${JSON.stringify(req.query || {}, null, 2)}`,
      });
    }

    const verified = verifyState(state, sessionSecret);
    if (!verified.ok) {
      res.status(400);
      return res.render('error', {
        title: 'state 校验失败',
        message: verified.error,
      });
    }

    const redirectUri = verified.payload?.redirectUri || fallbackRedirectUri;

    try {
      const tokenResp = await exchangeCodeForToken({
        clientId: config.feishuClientId,
        clientSecret: config.feishuClientSecret,
        code,
        redirectUri,
      });

      const data = tokenResp.data || tokenResp;
      const userAccessToken = data.access_token || null;
      if (userAccessToken) {
        req.session.feishu = {
          userAccessToken,
          refreshToken: data.refresh_token || null,
          expiresIn: data.expires_in || null,
          scope: data.scope || null,
          tokenType: data.token_type || null,
          obtainedAt: new Date().toISOString(),
        };
        if (requestLog) requestLog.pushEvent('feishu.oauth.token', { ok: true });
      }

      return res.redirect('/chat');
    } catch (err) {
      if (requestLog) {
        requestLog.pushEvent('feishu.oauth.error', {
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
      res.status(500);
      return res.render('error', {
        title: '获取 user_access_token 失败',
        message: String(err && err.stack ? err.stack : err),
      });
    }
  });
}

module.exports = {
  registerChatRoutes,
};
