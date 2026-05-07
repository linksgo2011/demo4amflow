const { listChatMessages, sendTextMessageToChat } = require('./im');
const { getUserAccessToken, ensureTokensFromCookies } = require('./user-token');

function registerFeishuApiRoutes({ app, config, sessionSecret, requestLog, eventsStore }) {
  app.get('/feishu/api/state', (req, res) => {
    res.json({
      chatId: config.feishuChatId,
      hasToken: Boolean(req.session?.feishu?.userAccessToken),
    });
  });

  app.get('/feishu/api/token', (req, res) => {
    ensureTokensFromCookies(req, sessionSecret);
    const token = req.session?.feishu?.userAccessToken || null;
    if (!token) return res.status(401).json({ error: 'missing_user_access_token' });
    const sessionFeishu = req.session?.feishu || null;
    return res.json({
      userAccessToken: token,
      expiresIn: sessionFeishu?.expiresIn || null,
      obtainedAt: sessionFeishu?.obtainedAt || null,
      refreshToken: sessionFeishu?.refreshToken ? 'present' : null,
    });
  });

  app.get('/feishu/api/messages', async (req, res) => {
    let userAccessToken;
    try {
      userAccessToken = await getUserAccessToken(req, config, sessionSecret);
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
        requestLog,
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
      userAccessToken = await getUserAccessToken(req, config, sessionSecret);
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
        requestLog,
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
