const { randomUUID } = require('node:crypto');
const { askAilyKnowledge, askAilyConversation, startAilySkill } = require('./aily');
const { getCookie, signToken, verifyTokenCookie } = require('./token-cookie');

const AILY_UID_COOKIE = 'aily_uid';
const AILY_SID_COOKIE = 'aily_sid';

function setSignedCookie(res, name, value, secret, { secure, maxAgeMs }) {
  const signed = signToken(value, secret);
  res.cookie(name, signed, {
    httpOnly: true,
    sameSite: 'lax',
    secure: Boolean(secure),
    path: '/',
    maxAge: maxAgeMs,
  });
}

function clearCookie(res, name) {
  res.clearCookie(name, { path: '/' });
}

function getSignedCookie(req, name, secret) {
  const v = getCookie(req, name);
  const verified = verifyTokenCookie(v, secret);
  return verified.ok ? verified.token : null;
}

function parseSkillAnswer(data) {
  const outputRaw = data?.output;
  if (typeof outputRaw !== 'string' || !outputRaw.trim()) return null;
  try {
    const parsed = JSON.parse(outputRaw);
    if (parsed && typeof parsed.output === 'string') return parsed.output;
  } catch {}
  return outputRaw;
}

function registerChatbotRoutes({ app, config, sessionSecret, requestLog }) {
  app.get('/chatbot', async (req, res) => {
    res.type('text/html');
    return res.render('feishu-chatbot', {
      hasCreds: Boolean(config.feishuClientId && config.feishuClientSecret),
      ailyAppId: config.feishuAilyAppId || '',
      ailySkillId: config.feishuAilySkillId || '',
      dataAssetIds: config.feishuAilyDataAssetIds || [],
      dataAssetTagIds: config.feishuAilyDataAssetTagIds || [],
    });
  });

  app.post('/feishu/api/chatbot/session/reset', (req, res) => {
    clearCookie(res, AILY_SID_COOKIE);
    res.json({ ok: true });
  });

  app.post('/feishu/api/chatbot/ask', async (req, res) => {
    const question = String(req.body?.question || '').trim();
    if (!question) return res.status(400).json({ error: 'missing_question' });

    if (!config.feishuAilyAppId) {
      return res.status(400).json({ error: 'missing_feishu_aily_app_id' });
    }

    if (!config.feishuClientId || !config.feishuClientSecret) {
      return res.status(400).json({ error: 'missing_feishu_app_credentials' });
    }

    try {
      const mode = String(req.body?.mode || 'knowledge').toLowerCase();
      const baseUrl = config.baseUrl || `${req.protocol}://${req.get('host')}`;
      const secure = baseUrl.startsWith('https://');

      let resp;
      let conversation = null;
      let skill = null;

      if (mode === 'conversation' || mode === 'multi') {
        let bizUserId = getSignedCookie(req, AILY_UID_COOKIE, sessionSecret);
        if (!bizUserId) {
          bizUserId = randomUUID();
          setSignedCookie(res, AILY_UID_COOKIE, bizUserId, sessionSecret, {
            secure,
            maxAgeMs: 30 * 24 * 60 * 60 * 1000,
          });
        }

        const sessionId = getSignedCookie(req, AILY_SID_COOKIE, sessionSecret);
        conversation = await askAilyConversation({
          clientId: config.feishuClientId,
          clientSecret: config.feishuClientSecret,
          appId: config.feishuAilyAppId,
          message: question,
          bizUserId,
          sessionId,
          requestLog,
        });

        if (conversation?.sessionId && conversation.sessionId !== sessionId) {
          setSignedCookie(res, AILY_SID_COOKIE, conversation.sessionId, sessionSecret, {
            secure,
            maxAgeMs: 7 * 24 * 60 * 60 * 1000,
          });
        }

        resp = { code: 0, data: conversation, msg: '' };
      } else if (mode === 'skill') {
        const skillId = String(req.body?.skillId || config.feishuAilySkillId || '').trim();
        if (!skillId) return res.status(400).json({ error: 'missing_skill_id' });

        const globalRaw = req.body?.skillGlobalVariable;
        let globalVariable = { query: question };
        if (globalRaw !== undefined && globalRaw !== null && String(globalRaw).trim() !== '') {
          try {
            const customGlobal = JSON.parse(String(globalRaw));
            globalVariable =
              customGlobal && typeof customGlobal === 'object'
                ? { ...customGlobal, query: question }
                : { query: question };
          } catch {
            return res.status(400).json({ error: 'invalid_skill_global_variable_json' });
          }
        }

        const skillResp = await startAilySkill({
          clientId: config.feishuClientId,
          clientSecret: config.feishuClientSecret,
          appId: config.feishuAilyAppId,
          skillId,
          globalVariable,
          requestLog,
        });

        skill = {
          skillId,
          globalVariable,
          raw: skillResp,
        };

        resp = skillResp;
      } else {
        resp = await askAilyKnowledge({
          clientId: config.feishuClientId,
          clientSecret: config.feishuClientSecret,
          appId: config.feishuAilyAppId,
          message: question,
          dataAssetIds: config.feishuAilyDataAssetIds || undefined,
          dataAssetTagIds: config.feishuAilyDataAssetTagIds || undefined,
          requestLog,
        });
      }

      if (requestLog) {
        requestLog.pushEvent('feishu.aily.ask', {
          appId: config.feishuAilyAppId,
          questionPreview: question.slice(0, 200),
          code: resp?.code ?? null,
        });
      }

      const data = resp?.data || null;
      const answer = conversation
        ? conversation.answer
        : skill
          ? parseSkillAnswer(data)
          : data?.message?.content || data?.faq_result?.answer || null;

      return res.json({
        answer,
        mode: conversation ? 'conversation' : skill ? 'skill' : 'knowledge',
        sessionId: conversation?.sessionId || null,
        runId: conversation?.runId || null,
        runStatus: conversation?.runStatus || null,
        skillId: skill?.skillId || null,
        hasAnswer: conversation
          ? Boolean(conversation.answer)
          : skill
            ? null
            : typeof data?.has_answer === 'boolean'
              ? data.has_answer
              : null,
        raw: resp,
      });
    } catch (err) {
      if (requestLog) {
        requestLog.pushEvent('feishu.aily.error', {
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
      return res.status(502).json({
        error: 'feishu_aily_error',
        message: String(err && err.message ? err.message : err),
        details: err && err.details ? err.details : null,
      });
    }
  });
}

module.exports = { registerChatbotRoutes };
