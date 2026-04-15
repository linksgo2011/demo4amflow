const { buildAuthorizeUrl, exchangeCodeForToken, refreshUserAccessToken } = require('./oauth');
const { getCookie, signToken, verifyTokenCookie } = require('./token-cookie');

const FEISHU_UAT_COOKIE = 'feishu_uat';
const FEISHU_RT_COOKIE = 'feishu_rt';

function setFeishuTokenCookie(res, { token, secret, secure }) {
  const signed = signToken(token, secret);
  res.cookie(FEISHU_UAT_COOKIE, signed, {
    httpOnly: true,
    sameSite: 'lax',
    secure: Boolean(secure),
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function setFeishuRefreshTokenCookie(res, { refreshToken, secret, secure }) {
  const signed = signToken(refreshToken, secret);
  res.cookie(FEISHU_RT_COOKIE, signed, {
    httpOnly: true,
    sameSite: 'lax',
    secure: Boolean(secure),
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function clearFeishuTokenCookie(res) {
  res.clearCookie(FEISHU_UAT_COOKIE, { path: '/' });
}

function clearFeishuRefreshTokenCookie(res) {
  res.clearCookie(FEISHU_RT_COOKIE, { path: '/' });
}

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
    const sessionToken = req.session?.feishu?.userAccessToken || null;
    let cookieToken = null;
    if (!sessionToken) {
      const cookieValue = getCookie(req, FEISHU_UAT_COOKIE);
      const verified = verifyTokenCookie(cookieValue, sessionSecret);
      if (verified.ok) {
        cookieToken = verified.token;
        req.session.feishu = { ...(req.session.feishu || {}), userAccessToken: cookieToken };
      }
    }

    const sessionRefresh = req.session?.feishu?.refreshToken || null;
    if (!sessionRefresh) {
      const cookieValue = getCookie(req, FEISHU_RT_COOKIE);
      const verified = verifyTokenCookie(cookieValue, sessionSecret);
      if (verified.ok) {
        req.session.feishu = { ...(req.session.feishu || {}), refreshToken: verified.token };
      }
    }

    const hasToken = Boolean(sessionToken || cookieToken);
    res.type('text/html');
    if (hasToken) {
      return res.render('feishu-chat-room', {
        baseUrl,
        chatId: config.feishuChatId,
        tokenPreview: String(sessionToken || cookieToken || '').slice(0, 12),
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
    clearFeishuTokenCookie(res);
    clearFeishuRefreshTokenCookie(res);
    res.redirect('/chat');
  });

  app.get('/chat/refresh', async (req, res) => {
    const baseUrl = config.baseUrl || resolveBaseUrlFromReq(req);
    if (!config.feishuClientId || !config.feishuClientSecret) {
      res.status(400);
      return res.render('error', {
        title: '缺少飞书配置',
        message: '请先配置 FEISHU_CLIENT_ID 与 FEISHU_CLIENT_SECRET。',
      });
    }

    let refreshToken = req.session?.feishu?.refreshToken || null;
    if (!refreshToken) {
      const cookieValue = getCookie(req, FEISHU_RT_COOKIE);
      const verified = verifyTokenCookie(cookieValue, sessionSecret);
      if (verified.ok) {
        refreshToken = verified.token;
        req.session.feishu = { ...(req.session.feishu || {}), refreshToken };
      }
    }
    if (!refreshToken) {
      res.status(400);
      return res.render('error', {
        title: '缺少 refresh_token',
        message: '请在授权时包含 offline_access scope，并确保首次换 token 时返回 refresh_token。',
      });
    }

    try {
      const tokenResp = await refreshUserAccessToken({
        clientId: config.feishuClientId,
        clientSecret: config.feishuClientSecret,
        refreshToken,
      });
      const data = tokenResp.data || tokenResp;
      const userAccessToken = data.access_token || null;
      if (userAccessToken) {
        req.session.feishu = {
          ...(req.session.feishu || {}),
          userAccessToken,
          refreshToken: data.refresh_token || null,
          expiresIn: data.expires_in || null,
          refreshTokenExpiresIn: data.refresh_token_expires_in || null,
          scope: data.scope || null,
          tokenType: data.token_type || null,
          obtainedAt: new Date().toISOString(),
        };
        setFeishuTokenCookie(res, { token: userAccessToken, secret: sessionSecret, secure: baseUrl.startsWith('https://') });
        if (data.refresh_token) {
          setFeishuRefreshTokenCookie(res, {
            refreshToken: data.refresh_token,
            secret: sessionSecret,
            secure: baseUrl.startsWith('https://'),
          });
        }
      }
      if (requestLog) requestLog.pushEvent('feishu.oauth.refresh', { ok: true });
      return res.redirect('/chat');
    } catch (err) {
      if (requestLog) {
        requestLog.pushEvent('feishu.oauth.refresh_error', {
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
      res.status(500);
      return res.render('error', {
        title: '刷新 user_access_token 失败',
        message:
          String(err && err.stack ? err.stack : err) +
          (err && err.details ? `\n\nDETAILS:\n${JSON.stringify(err.details, null, 2)}` : ''),
      });
    }
  });

  app.post('/chat/token', (req, res) => {
    const token = String(req.body?.userAccessToken || '').trim();
    if (!token) {
      res.status(400);
      return res.render('error', { title: '参数错误', message: 'userAccessToken 不能为空' });
    }
    req.session.feishu = { userAccessToken: token, setAt: new Date().toISOString() };
    setFeishuTokenCookie(res, { token, secret: sessionSecret, secure: (config.baseUrl || '').startsWith('https://') });
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
        setFeishuTokenCookie(res, { token: userAccessToken, secret: sessionSecret, secure: baseUrl.startsWith('https://') });
        if (data.refresh_token) {
          setFeishuRefreshTokenCookie(res, {
            refreshToken: data.refresh_token,
            secret: sessionSecret,
            secure: baseUrl.startsWith('https://'),
          });
        }
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
