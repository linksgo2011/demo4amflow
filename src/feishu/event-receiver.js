function verifyToken({ expected, got }) {
  if (!expected) return true;
  return expected === got;
}

function registerFeishuEventReceiver({ app, config, requestLog, eventsStore }) {
  app.get('/feishu/events/receive', (_req, res) => {
    res.type('application/json');
    res.send(
      JSON.stringify(
        {
          ok: true,
          method: 'GET',
          note: 'Feishu event callback uses POST. This endpoint is for connectivity checks only.',
        },
        null,
        2,
      ),
    );
  });

  app.post('/feishu/events/receive', (req, res) => {
    const body = req.body || {};

    if (body.challenge) {
      if (!verifyToken({ expected: config.feishuVerificationToken, got: body.token })) {
        if (requestLog) requestLog.pushEvent('feishu.event.verify_fail', { reason: 'token_mismatch' });
        return res.status(401).json({ error: 'invalid_token' });
      }
      if (requestLog) requestLog.pushEvent('feishu.event.url_verification', { ok: true });
      return res.status(200).json({ challenge: body.challenge });
    }

    if (body.encrypt) {
      if (requestLog) requestLog.pushEvent('feishu.event.encrypted', { note: 'encrypt_not_supported' });
      return res.status(400).json({ error: 'encrypted_event_not_supported' });
    }

    if (!verifyToken({ expected: config.feishuVerificationToken, got: body.token })) {
      if (requestLog) requestLog.pushEvent('feishu.event.verify_fail', { reason: 'token_mismatch' });
      return res.status(401).json({ error: 'invalid_token' });
    }

    if (eventsStore) {
      eventsStore.push({
        type: 'event_callback',
        header: body.header || null,
        event: body.event || null,
      });
    }
    if (requestLog) {
      requestLog.pushEvent('feishu.event.receive', {
        header: body.header || null,
        eventType: body?.header?.event_type || null,
      });
    }

    return res.json({ ok: true });
  });
}

module.exports = { registerFeishuEventReceiver };
