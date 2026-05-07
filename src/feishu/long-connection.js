function startFeishuLongConnection({ config, requestLog, eventsStore }) {
  const appId = config.feishuClientId;
  const appSecret = config.feishuClientSecret;
  if (!appId || !appSecret) {
    const err = new Error('ERR_MISSING_FEISHU_APP_CREDENTIALS');
    err.details = { need: ['FEISHU_CLIENT_ID', 'FEISHU_CLIENT_SECRET'] };
    throw err;
  }

  const Lark = require('@larksuiteoapi/node-sdk');
  const client = new Lark.Client({ appId, appSecret });
  const logger = {
    error: (...msg) => console.error('[feishu-ws]', ...msg),
    warn: (...msg) => console.warn('[feishu-ws]', ...msg),
    info: (...msg) => console.info('[feishu-ws]', ...msg),
    debug: (...msg) => console.debug('[feishu-ws]', ...msg),
    trace: (...msg) => console.debug('[feishu-ws]', ...msg),
  };
  const wsClient = new Lark.WSClient({
    appId,
    appSecret,
    logger,
    loggerLevel: Lark.LoggerLevel.debug,
  });

  console.info('[feishu-ws] start', JSON.stringify({ appId }, null, 2));
  if (requestLog) requestLog.pushEvent('feishu.ws.start', { appId });

  const dispatcher = new Lark.EventDispatcher({}).register({
    'im.message.receive_v1': async (data) => {
      const evt = data || {};
      if (eventsStore) {
        eventsStore.push({
          type: 'ws_event',
          eventType: 'im.message.receive_v1',
          data: evt,
        });
      }
      if (requestLog) {
        requestLog.pushEvent('feishu.ws.event', {
          eventType: 'im.message.receive_v1',
          chatId: evt?.event?.message?.chat_id || null,
          messageId: evt?.event?.message?.message_id || null,
        });
      }
    },
  });

  wsClient.start({ eventDispatcher: dispatcher });

  return { client, wsClient };
}

module.exports = { startFeishuLongConnection };
