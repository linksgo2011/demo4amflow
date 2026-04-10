const { listChatMessages, sendTextMessageToChat } = require('./im');
const { refreshUserAccessToken } = require('./oauth');

function msUntilExpiry(sessionFeishu) {
  const expiresIn = Number(sessionFeishu?.expiresIn || 0);
  const obtainedAt = sessionFeishu?.obtainedAt ? Date.parse(sessionFeishu.obtainedAt) : 0;
  if (!expiresIn || !obtainedAt) return null;
  return obtainedAt + expiresIn * 1000 - Date.now();
}

async function getUserAccessToken(req, config) {
  const sessionFeishu = req.session?.feishu || null;
  const token = sessionFeishu?.userAccessToken || null;
  if (!token) return null;

  const leftMs = msUntilExpiry(sessionFeishu);
  if (leftMs === null) return token;
  if (leftMs > 60 * 1000) return token;

  const refreshToken = sessionFeishu?.refreshToken || null;
  if (!refreshToken) return token;
  if (!config.feishuClientId || !config.feishuClientSecret) return token;

  const tokenResp = await refreshUserAccessToken({
    clientId: config.feishuClientId,
    clientSecret: config.feishuClientSecret,
    refreshToken,
  });
  const data = tokenResp.data || tokenResp;
  const newAccessToken = data.access_token || null;
  if (!newAccessToken) return token;

  req.session.feishu = {
    ...(req.session.feishu || {}),
    userAccessToken: newAccessToken,
    refreshToken: data.refresh_token || null,
    expiresIn: data.expires_in || null,
    refreshTokenExpiresIn: data.refresh_token_expires_in || null,
    scope: data.scope || null,
    tokenType: data.token_type || null,
    obtainedAt: new Date().toISOString(),
  };

  return newAccessToken;
}

function registerFeishuApiRoutes({ app, config, requestLog, eventsStore }) {
  app.get('/feishu/api/state', (req, res) => {
    res.json({
      chatId: config.feishuChatId,
      hasToken: Boolean(req.session?.feishu?.userAccessToken),
    });
  });

  app.get('/feishu/api/token', (req, res) => {
    const sessionFeishu = req.session?.feishu || null;
    const userAccessToken = sessionFeishu?.userAccessToken || null;
    if (!userAccessToken) return res.status(401).json({ error: 'missing_user_access_token' });
    return res.json({
      userAccessToken,
      expiresIn: sessionFeishu?.expiresIn || null,
      obtainedAt: sessionFeishu?.obtainedAt || null,
      refreshToken: sessionFeishu?.refreshToken ? 'present' : null,
    });
  });

  app.get('/feishu/api/messages', async (req, res) => {
    let userAccessToken;
    try {
      userAccessToken = await getUserAccessToken(req, config);
    } catch (err) {
      if (requestLog) {
        requestLog.pushEvent('feishu.oauth.refresh_error', {
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
      return res.status(502).json({
        error: 'feishu_refresh_error',
        message: String(err && err.message ? err.message : err),
        details: err && err.details ? err.details : null,
      });
    }
    if (!userAccessToken) return res.status(401).json({ error: 'missing_user_access_token' });

    try {
      const result = await listChatMessages({
        userAccessToken,
        chatId: config.feishuChatId,
        pageSize: Math.min(Number.parseInt(String(req.query?.pageSize || '20'), 10) || 20, 50),
        pageToken: req.query?.pageToken ? String(req.query.pageToken) : null,
      });
      if (requestLog) {
        requestLog.pushEvent('feishu.im.list', {
          chatId: config.feishuChatId,
          count: result.items.length,
          hasMore: result.hasMore,
        });
      }
      return res.json(result);
    } catch (err) {
      if (requestLog) {
        requestLog.pushEvent('feishu.im.error', {
          action: 'list',
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
      return res.status(502).json({
        error: 'feishu_api_error',
        message: String(err && err.message ? err.message : err),
        details: err && err.details ? err.details : null,
      });
    }
  });

  app.post('/feishu/api/messages', async (req, res) => {
    let userAccessToken;
    try {
      userAccessToken = await getUserAccessToken(req, config);
    } catch (err) {
      if (requestLog) {
        requestLog.pushEvent('feishu.oauth.refresh_error', {
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
      return res.status(502).json({
        error: 'feishu_refresh_error',
        message: String(err && err.message ? err.message : err),
        details: err && err.details ? err.details : null,
      });
    }
    if (!userAccessToken) return res.status(401).json({ error: 'missing_user_access_token' });

    const text = String(req.body?.text || '').trim();
    if (!text) return res.status(400).json({ error: 'missing_text' });

    try {
      const result = await sendTextMessageToChat({
        userAccessToken,
        chatId: config.feishuChatId,
        text,
      });
      if (requestLog) {
        requestLog.pushEvent('feishu.im.send', {
          chatId: config.feishuChatId,
          textPreview: text.slice(0, 200),
        });
      }
      return res.json(result);
    } catch (err) {
      if (requestLog) {
        requestLog.pushEvent('feishu.im.error', {
          action: 'send',
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
      return res.status(502).json({
        error: 'feishu_api_error',
        message: String(err && err.message ? err.message : err),
        details: err && err.details ? err.details : null,
      });
    }
  });

  app.get('/feishu/api/events', (req, res) => {
    return res.json({ items: eventsStore ? eventsStore.list() : [] });
  });

  app.post('/feishu/api/events/clear', (req, res) => {
    if (eventsStore) eventsStore.clear();
    res.json({ ok: true });
  });
}

module.exports = { registerFeishuApiRoutes };
