const { getTenantAccessToken } = require('./app-access-token');
const { randomUUID } = require('node:crypto');

function isStdoutEnabled() {
  const v = String(process.env.DEBUG_FEISHU_HTTP || '').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

async function fetchAilyJson({ method, url, token, headers, body, requestLog }) {
  const reqLog = {
    method,
    url,
    headers: {
      authorization: 'Bearer ***',
      ...(headers || {}),
    },
    body: body || null,
  };
  if (requestLog) requestLog.pushEvent('feishu.http.request', reqLog);
  if (isStdoutEnabled()) console.log('[feishu-http] request', JSON.stringify(reqLog));

  const resp = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(headers || {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const contentType = String(resp.headers.get('content-type') || '');
  const text = await resp.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    const err = new Error('ERR_FEISHU_AILY_NON_JSON');
    err.details = { status: resp.status, contentType, text: String(text).slice(0, 8000) };
    const resLog = { method, url, status: resp.status, contentType, bodyText: String(text).slice(0, 8000) };
    if (requestLog) requestLog.pushEvent('feishu.http.response', resLog);
    if (isStdoutEnabled()) console.log('[feishu-http] response', JSON.stringify(resLog));
    throw err;
  }

  const resLog = { method, url, status: resp.status, contentType, body: json };
  if (requestLog) requestLog.pushEvent('feishu.http.response', resLog);
  if (isStdoutEnabled()) console.log('[feishu-http] response', JSON.stringify(resLog));

  if (!resp.ok) {
    const err = new Error('ERR_FEISHU_AILY_HTTP');
    err.details = { status: resp.status, contentType, body: json };
    throw err;
  }
  if (json && typeof json.code === 'number' && json.code !== 0) {
    const err = new Error('ERR_FEISHU_AILY_CODE');
    err.details = { code: json.code, msg: json.msg, body: json };
    throw err;
  }

  return json;
}

async function askAilyKnowledge({
  clientId,
  clientSecret,
  appId,
  message,
  dataAssetIds,
  dataAssetTagIds,
  requestLog,
}) {
  const tenantAccessToken = await getTenantAccessToken({ clientId, clientSecret, requestLog });

  const url = `https://open.feishu.cn/open-apis/aily/v1/apps/${encodeURIComponent(appId)}/knowledges/ask`;
  const body = {
    message: { content: message },
    ...(dataAssetIds ? { data_asset_ids: dataAssetIds } : {}),
    ...(dataAssetTagIds ? { data_asset_tag_ids: dataAssetTagIds } : {}),
  };

  if (requestLog) {
    requestLog.pushEvent('feishu.http.request', {
      method: 'POST',
      url,
      headers: {
        authorization: 'Bearer ***',
        'content-type': 'application/json; charset=utf-8',
        accept: 'text/event-stream, application/json',
      },
      body,
    });
  }
  if (isStdoutEnabled()) {
    console.log(
      '[feishu-http] request',
      JSON.stringify({
        method: 'POST',
        url,
        headers: {
          authorization: 'Bearer ***',
          'content-type': 'application/json; charset=utf-8',
          accept: 'text/event-stream, application/json',
        },
        body,
      }),
    );
  }

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${tenantAccessToken}`,
      'content-type': 'application/json; charset=utf-8',
      accept: 'text/event-stream, application/json',
    },
    body: JSON.stringify(body),
  });

  const contentType = String(resp.headers.get('content-type') || '');
  if (!resp.ok) {
    const text = await resp.text();
    const err = new Error('ERR_FEISHU_AILY_HTTP');
    err.details = { status: resp.status, contentType, text: String(text).slice(0, 8000) };
    if (requestLog) {
      requestLog.pushEvent('feishu.http.response', {
        method: 'POST',
        url,
        status: resp.status,
        contentType,
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
          contentType,
          bodyText: String(text).slice(0, 8000),
        }),
      );
    }
    throw err;
  }

  if (contentType.includes('application/json')) {
    const json = await resp.json();
    if (requestLog) {
      requestLog.pushEvent('feishu.http.response', {
        method: 'POST',
        url,
        status: resp.status,
        contentType,
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
          contentType,
          body: json,
        }),
      );
    }
    return json;
  }

  if (!contentType.includes('text/event-stream')) {
    const text = await resp.text();
    const err = new Error('ERR_FEISHU_AILY_UNEXPECTED_CONTENT_TYPE');
    err.details = { contentType, text: String(text).slice(0, 8000) };
    if (requestLog) {
      requestLog.pushEvent('feishu.http.response', {
        method: 'POST',
        url,
        status: resp.status,
        contentType,
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
          contentType,
          bodyText: String(text).slice(0, 8000),
        }),
      );
    }
    throw err;
  }

  const reader = resp.body.getReader();
  let buffer = '';
  let lastJson = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += Buffer.from(value).toString('utf8');

    while (true) {
      const idx = buffer.indexOf('\n\n');
      if (idx === -1) break;
      const frame = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);

      const lines = frame.split('\n');
      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        const data = line.slice(5).trim();
        if (!data) continue;
        try {
          const json = JSON.parse(data);
          lastJson = json;
          const status = json?.data?.status;
          if (status === 'finished') {
            try { reader.cancel(); } catch {}
            if (requestLog) {
              requestLog.pushEvent('feishu.http.response', {
                method: 'POST',
                url,
                status: resp.status,
                contentType,
                body: lastJson,
              });
            }
            if (isStdoutEnabled()) {
              console.log(
                '[feishu-http] response',
                JSON.stringify({
                  method: 'POST',
                  url,
                  status: resp.status,
                  contentType,
                  body: lastJson,
                }),
              );
            }
            return lastJson;
          }
        } catch {}
      }
    }
  }

  if (lastJson) {
    if (requestLog) {
      requestLog.pushEvent('feishu.http.response', {
        method: 'POST',
        url,
        status: resp.status,
        contentType,
        body: lastJson,
      });
    }
    if (isStdoutEnabled()) {
      console.log(
        '[feishu-http] response',
        JSON.stringify({
          method: 'POST',
          url,
          status: resp.status,
          contentType,
          body: lastJson,
        }),
      );
    }
    return lastJson;
  }
  const err = new Error('ERR_FEISHU_AILY_EMPTY_SSE');
  err.details = { contentType };
  throw err;
}

async function askAilyConversation({
  clientId,
  clientSecret,
  appId,
  message,
  bizUserId,
  sessionId,
  requestLog,
}) {
  const token = await getTenantAccessToken({ clientId, clientSecret, requestLog });
  const base = 'https://open.feishu.cn/open-apis/aily/v1';

  let sid = sessionId || null;
  if (!sid) {
    const createSession = await fetchAilyJson({
      method: 'POST',
      url: `${base}/sessions`,
      token,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        ...(bizUserId ? { 'x-aily-bizuserid': String(bizUserId) } : {}),
      },
      body: {},
      requestLog,
    });
    sid = createSession?.data?.session?.id || null;
  }

  if (!sid) {
    const err = new Error('ERR_FEISHU_AILY_MISSING_SESSION_ID');
    err.details = { sessionId: sid };
    throw err;
  }

  const createMessage = await fetchAilyJson({
    method: 'POST',
    url: `${base}/sessions/${encodeURIComponent(sid)}/messages`,
    token,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: {
      idempotent_id: randomUUID(),
      content_type: 'TEXT',
      content: String(message),
    },
    requestLog,
  });
  const userMessageId = createMessage?.data?.message?.id || null;

  const createRun = await fetchAilyJson({
    method: 'POST',
    url: `${base}/sessions/${encodeURIComponent(sid)}/runs`,
    token,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: { app_id: String(appId) },
    requestLog,
  });
  const runId = createRun?.data?.run?.id || null;

  const endStatuses = new Set(['COMPLETED', 'REQUIRES_MESSAGE', 'EXPIRED', 'CANCELLED', 'FAILED']);
  let runStatus = createRun?.data?.run?.status || null;
  let answer = null;
  let assistantMessageId = null;
  let lastMessages = null;

  for (let i = 0; i < 120; i += 1) {
    await new Promise((r) => setTimeout(r, 500));

    const runResp = await fetchAilyJson({
      method: 'GET',
      url: `${base}/sessions/${encodeURIComponent(sid)}/runs/${encodeURIComponent(runId)}`,
      token,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      requestLog,
    });
    runStatus = runResp?.data?.run?.status || runStatus;

    const msgUrl = new URL(`${base}/sessions/${encodeURIComponent(sid)}/messages`);
    msgUrl.searchParams.set('run_id', String(runId));
    msgUrl.searchParams.set('with_partial_message', 'true');
    const msgResp = await fetchAilyJson({
      method: 'GET',
      url: msgUrl.toString(),
      token,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      requestLog,
    });
    const messages = msgResp?.data?.messages || [];
    lastMessages = messages;

    const assistants = messages.filter((m) => m?.sender?.sender_type === 'ASSISTANT');
    const last = assistants.length ? assistants[assistants.length - 1] : null;
    if (last?.content) {
      answer = last.content;
      assistantMessageId = last.id || assistantMessageId;
    }

    if (runStatus && endStatuses.has(runStatus)) break;
  }

  return {
    sessionId: sid,
    runId,
    runStatus,
    answer,
    userMessageId,
    assistantMessageId,
    messages: lastMessages,
  };
}

async function startAilySkill({
  clientId,
  clientSecret,
  appId,
  skillId,
  input,
  globalVariable,
  requestLog,
}) {
  const token = await getTenantAccessToken({ clientId, clientSecret, requestLog });
  const url = `https://open.feishu.cn/open-apis/aily/v1/apps/${encodeURIComponent(appId)}/skills/${encodeURIComponent(skillId)}/start`;
  const body = {};
  if (globalVariable) body.global_variable = globalVariable;
  if (input !== undefined && input !== null) body.input = String(input);

  return fetchAilyJson({
    method: 'POST',
    url,
    token,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body,
    requestLog,
  });
}

module.exports = {
  askAilyKnowledge,
  askAilyConversation,
  startAilySkill,
};
