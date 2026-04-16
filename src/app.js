require('dotenv').config();

const saml = require('samlify');
const express = require('express');
const session = require('express-session');

const { config, resolveBaseUrlFromReq } = require('./config');
const { createRequestLog } = require('./request-log');
const { ensureSigningMaterial } = require('./saml/cert');
const { createIdp } = require('./saml/idp');
const { FEISHU_SP_METADATA_XML } = require('./saml/default-sp-metadata');
const { createSpRegistry } = require('./saml/sp-registry');
const { decodeSamlMaybe } = require('./saml/saml-message');
const { signState, verifyState } = require('./saml/state');
const { registerChatRoutes } = require('./feishu/chat-routes');
const { registerFeishuApiRoutes } = require('./feishu/im-routes');
const { registerFeishuEventReceiver } = require('./feishu/event-receiver');
const { createEventsStore } = require('./feishu/events-store');
const { startFeishuLongConnection } = require('./feishu/long-connection');
const { buildConsultLoginUrl } = require('./feishu/consult');

function isVercel() {
  return Boolean(process.env.VERCEL);
}

async function createApp() {
  if (isVercel() || config.disableSchemaValidation) {
    saml.setSchemaValidator({
      validate: async () => 'SKIPPED_VALIDATE_XML',
    });
  } else {
    const { validate } = require('@authenio/samlify-xsd-schema-validator');
    saml.setSchemaValidator({ validate });
  }

  const app = express();

  app.set('trust proxy', config.trustProxy);
  app.set('view engine', 'ejs');
  app.set('views', [`${__dirname}/views`, `${__dirname}/feishu/views`]);

  app.use(express.urlencoded({ extended: false, limit: '2mb' }));
  app.use(express.json({ limit: '2mb' }));

  const requestLog = createRequestLog({ max: config.logMax });
  app.use(['/saml', '/feishu'], requestLog.middleware);

  const feishuEvents = createEventsStore({ max: 200 });

  const sessionSecret = config.sessionSecret || `dev-${Math.random().toString(16).slice(2)}`;

  app.use(
    session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
      },
    }),
  );

  const allowGenerate = !isVercel() || config.allowEphemeralCert;
  const signingMaterial = await ensureSigningMaterial({
    keyPath: config.keyPath,
    certPath: config.certPath,
    commonName: 'demo4amflow-idp',
    privateKeyPem: config.idpPrivateKeyPem,
    certPem: config.idpCertPem,
    allowGenerate,
    writeToDisk: !isVercel(),
  });

  const spRegistry = createSpRegistry();
  if (config.spMetadataXml) {
    spRegistry.setFromXml(config.spMetadataXml);
  } else if (config.spMetadataPath) {
    spRegistry.loadFromPath(config.spMetadataPath);
  } else {
    spRegistry.setFromXml(FEISHU_SP_METADATA_XML);
  }

  const idpCache = new Map();
  function getIdpContext(req) {
    const baseUrl = config.baseUrl || resolveBaseUrlFromReq(req);
    if (idpCache.has(baseUrl)) return idpCache.get(baseUrl);
    const ctx = createIdp({
      baseUrl,
      entityId: config.idpEntityId,
      privateKeyPem: signingMaterial.privateKeyPem,
      certForMetadata: signingMaterial.certForMetadata,
    });
    const full = {
      ...ctx,
      baseUrl,
      certPem: signingMaterial.certPem,
      certForMetadata: signingMaterial.certForMetadata,
    };
    idpCache.set(baseUrl, full);
    return full;
  }

  if (isVercel() && !config.baseUrl) {
    console.warn('在 Vercel 环境建议设置 BASE_URL（否则 metadata 的 issuer/endpoints 可能因域名/协议变化而不稳定）');
  }
  if (isVercel() && !(config.idpPrivateKeyPem && config.idpCertPem)) {
    console.warn('在 Vercel 环境建议设置 IDP_PRIVATE_KEY_PEM 与 IDP_CERT_PEM（避免每次冷启动导致证书变化）');
  }

  app.get('/', (_req, res) => res.render('home'));

  app.get('/consult', (req, res) => {
    const baseUrl = config.baseUrl || resolveBaseUrlFromReq(req);
    const redirectUri = `${baseUrl}/chat/callback`;

    if (!config.feishuClientId) {
      res.status(400);
      return res.render('error', {
        title: '缺少飞书配置',
        message: '请先配置 FEISHU_CLIENT_ID。',
      });
    }

    const scope =
      config.feishuConsultScope ||
      config.feishuScope ||
      'contact:user.employee_id:readonly offline_access';

    const state = signState(
      {
        redirectUri,
        at: Date.now(),
      },
      sessionSecret,
      24 * 60 * 60,
    );

    const url = buildConsultLoginUrl({
      clientId: config.feishuClientId,
      redirectUri,
      scope,
      state,
      passportAppId: config.feishuPassportAppId,
      autoSsoDomain: config.feishuAutoSsoDomain,
    });

    return res.redirect(url);
  });

  app.get('/saml/idp/metadata', (req, res) => {
    const { idp } = getIdpContext(req);
    res.type('application/xml');
    res.send(idp.getMetadata());
  });

  registerChatRoutes({
    app,
    config,
    resolveBaseUrlFromReq,
    sessionSecret,
    signState,
    verifyState,
    requestLog,
  });

  registerFeishuApiRoutes({
    app,
    config,
    sessionSecret,
    requestLog,
    eventsStore: feishuEvents,
  });

  registerFeishuEventReceiver({
    app,
    config,
    requestLog,
    eventsStore: feishuEvents,
  });

  if (config.feishuLongConnection) {
    if (isVercel()) {
      console.warn('FEISHU_LONG_CONNECTION 已开启，但 Vercel Serverless 不适合运行长连接。请在本地或常驻服务器运行。');
    } else {
      try {
        startFeishuLongConnection({
          config,
          requestLog,
          eventsStore: feishuEvents,
        });
        requestLog.pushEvent('feishu.ws.started', { ok: true });
      } catch (err) {
        requestLog.pushEvent('feishu.ws.error', {
          error: String(err && err.stack ? err.stack : err),
          details: err && err.details ? err.details : null,
        });
      }
    }
  }

  app.all('/saml/idp/sso', async (req, res) => {
    const spEntry = spRegistry.get();
    if (!spEntry) {
      res.status(400);
      return res.render('error', {
        title: 'SP 未配置',
        message: '请先在 /idp/sp 粘贴并保存 SP Metadata。',
      });
    }

    const binding = req.method === 'POST' ? 'post' : 'redirect';
    const { idp } = getIdpContext(req);

    try {
      const parseResult = await idp.parseLoginRequest(spEntry.sp, binding, req);
      const samlRequestRaw =
        binding === 'post' ? req.body?.SAMLRequest : req.query?.SAMLRequest;
      const relayState =
        (binding === 'post' ? req.body?.RelayState : req.query?.RelayState) ||
        null;

      const receivedAt = new Date().toISOString();
      const extract = parseResult?.extract || null;
      const requestId = extract?.request?.id || null;

      const decoded = decodeSamlMaybe(samlRequestRaw);
      requestLog.pushEvent('saml.request', {
        binding,
        relayState,
        requestId,
        spIssuer: extract?.issuer || null,
        destination: extract?.request?.destination || null,
        samlRequestLength: samlRequestRaw ? String(samlRequestRaw).length : 0,
        samlRequestDecodedEncoding: decoded?.encoding || null,
        samlRequestDecodedXml: decoded?.xml ? String(decoded.xml).slice(0, 12000) : null,
      });

      const state = signState(
        {
          binding,
          relayState,
          receivedAt,
          requestId,
          spIssuer: extract?.issuer || null,
          destination: extract?.request?.destination || null,
        },
        sessionSecret,
        24 * 60 * 60,
      );

      requestLog.pushEvent('saml.sso.parsed', {
        binding,
        relayState,
        requestId,
        spIssuer: extract?.issuer || null,
        destination: extract?.request?.destination || null,
      });

      if (config.debugSaml) {
        console.log(
          JSON.stringify(
            {
              event: 'saml.sso.parsed',
              binding,
              relayState,
              requestId,
              spIssuer: extract?.issuer || null,
              destination: extract?.request?.destination || null,
              samlRequestLength: samlRequestRaw ? String(samlRequestRaw).length : 0,
            },
            null,
            2,
          ),
        );
      }

      req.session.saml = {
        binding,
        relayState,
        samlRequestRaw: samlRequestRaw || null,
        requestInfo: parseResult,
        receivedAt,
        state,
      };

      return res.redirect(`/idp/login?state=${encodeURIComponent(state)}`);
    } catch (err) {
      requestLog.pushEvent('saml.sso.error', {
        binding,
        error: String(err && err.stack ? err.stack : err),
      });
      if (config.debugSaml) {
        console.log(
          JSON.stringify(
            {
              event: 'saml.sso.error',
              binding,
              error: String(err && err.stack ? err.stack : err),
            },
            null,
            2,
          ),
        );
      }
      res.status(400);
      return res.render('error', {
        title: '解析 AuthnRequest 失败',
        message: String(err && err.stack ? err.stack : err),
      });
    }
  });

  app.get('/idp/info', (req, res) => {
    const ctx = getIdpContext(req);
    const spEntry = spRegistry.get();
    res.render('info', {
      ctx,
      spEntry,
      config: {
        ...config,
        keyPath: undefined,
        certPath: undefined,
        sessionSecret: undefined,
        idpPrivateKeyPem: undefined,
        idpCertPem: undefined,
        spMetadataXml: undefined,
      },
    });
  });

  app.get('/idp/sp', (_req, res) => {
    const spEntry = spRegistry.get();
    res.render('sp', {
      spEntry,
      prefill: spEntry?.metadataXml || '',
    });
  });

  app.post('/idp/sp', (req, res) => {
    const xml = String(req.body?.metadataXml || '').trim();
    if (!xml) {
      res.status(400);
      return res.render('error', {
        title: '参数错误',
        message: 'metadataXml 不能为空',
      });
    }
    try {
      spRegistry.setFromXml(xml);
      return res.redirect('/idp/info');
    } catch (err) {
      res.status(400);
      return res.render('error', {
        title: '解析 SP Metadata 失败',
        message: String(err && err.stack ? err.stack : err),
      });
    }
  });

  app.get('/idp/login', (req, res) => {
    const stateToken = req.query?.state ? String(req.query.state) : null;
    if (stateToken) {
      const verified = verifyState(stateToken, sessionSecret);
      if (!verified.ok) {
        res.status(400);
        return res.render('error', {
          title: '登录状态无效',
          message: verified.error,
        });
      }

      const p = verified.payload;
      const saml = {
        binding: p.binding,
        relayState: p.relayState,
        receivedAt: p.receivedAt,
        samlRequestRaw: null,
        requestId: p.requestId,
        state: stateToken,
      };
      const extract = p.spIssuer || p.destination || p.requestId ? {
        issuer: p.spIssuer,
        request: {
          id: p.requestId,
          destination: p.destination,
        },
      } : null;

      return res.render('login', {
        saml,
        extract,
        samlRequestDecoded: null,
      });
    }

    const samlSession = req.session.saml || null;
    if (!samlSession) {
      res.status(400);
      return res.render('error', {
        title: '没有待处理的 SAML 请求',
        message: '请从 SP 发起 SSO 请求（AuthnRequest）到 /saml/idp/sso。',
      });
    }

    const extract = samlSession.requestInfo?.extract || null;

    return res.render('login', {
      saml: samlSession,
      extract,
      samlRequestDecoded: decodeSamlMaybe(samlSession.samlRequestRaw),
    });
  });

  app.post('/idp/login', async (req, res) => {
    let samlSession = req.session.saml || null;
    const stateToken = req.body?.state ? String(req.body.state) : null;
    if (stateToken) {
      const verified = verifyState(stateToken, sessionSecret);
      if (!verified.ok) {
        res.status(400);
        return res.render('error', {
          title: '登录状态无效',
          message: verified.error,
        });
      }
      const p = verified.payload;
      samlSession = {
        binding: p.binding,
        relayState: p.relayState,
        receivedAt: p.receivedAt,
        samlRequestRaw: null,
        requestInfo: p.requestId ? { extract: { request: { id: p.requestId } } } : null,
      };
    }

    if (!samlSession || !samlSession.requestInfo) {
      requestLog.pushEvent('saml.login.error', { error: 'missing_request_context' });
      res.status(400);
      return res.render('error', {
        title: '没有待处理的 SAML 请求',
        message: '未找到 AuthnRequest 上下文。请重新从 SP 发起登录。',
      });
    }

    const spEntry = spRegistry.get();
    if (!spEntry) {
      res.status(400);
      return res.render('error', {
        title: 'SP 未配置',
        message: '请先在 /idp/sp 配置 SP Metadata。',
      });
    }

    const email = String(req.body?.email || '').trim();
    if (!email) {
      res.status(400);
      return res.render('error', {
        title: '参数错误',
        message: 'email 不能为空',
      });
    }

    const user = {
      email,
      displayName: String(req.body?.displayName || '').trim() || undefined,
      uid: String(req.body?.uid || '').trim() || undefined,
    };

    const { idp } = getIdpContext(req);
    try {
      const nowTime = new Date();
      const fiveMinutesLaterTime = new Date(nowTime.getTime());
      fiveMinutesLaterTime.setMinutes(fiveMinutesLaterTime.getMinutes() + 5);

      const now = nowTime.toISOString();
      const fiveMinutesLater = fiveMinutesLaterTime.toISOString();

      const spEntityID = spEntry.sp.entityMeta.getEntityID();
      const acs = spEntry.sp.entityMeta.getAssertionConsumerService('post');
      if (!acs) {
        res.status(400);
        return res.render('error', {
          title: 'SP Metadata 不完整',
          message:
            '未找到 HTTP-POST 的 AssertionConsumerService（ACS）。请确认 SP Metadata 中存在 POST ACS 端点。',
        });
      }
      const responseId = `_${Math.random().toString(16).slice(2)}${Math.random()
        .toString(16)
        .slice(2)}`;
      const assertionId = `_${Math.random().toString(16).slice(2)}${Math.random()
        .toString(16)
        .slice(2)}`;
      const inResponseTo = samlSession.requestInfo?.extract?.request?.id || '';
      const issuer = idp.entityMeta.getEntityID();

      const authnStatement = `<saml:AuthnStatement AuthnInstant="${now}" SessionIndex="${responseId}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`;

      const tagValues = {
        ID: responseId,
        AssertionID: assertionId,
        Destination: acs,
        Audience: spEntityID,
        EntityID: spEntityID,
        SubjectRecipient: acs,
        Issuer: issuer,
        IssueInstant: now,
        AssertionConsumerServiceURL: acs,
        StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
        ConditionsNotBefore: now,
        ConditionsNotOnOrAfter: fiveMinutesLater,
        SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
        NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        NameID: user.email,
        InResponseTo: inResponseTo,
        AuthnStatement: authnStatement,
        attrEmail: user.email,
        attrDisplayName: user.displayName || '',
        attrUid: user.uid || '',
      };

      const response = await idp.createLoginResponse(
        spEntry.sp,
        samlSession.requestInfo,
        'post',
        user,
        (template) => ({
          context: saml.SamlLib.replaceTagsByValue(template, tagValues),
        }),
        undefined,
        samlSession.relayState || undefined,
      );

      requestLog.pushEvent('saml.login.response', {
        inResponseTo,
        relayState: samlSession.relayState || null,
        entityEndpoint: response.entityEndpoint,
        samlResponseLength: response.context ? String(response.context).length : 0,
      });

      let samlResponseXml = null;
      try {
        samlResponseXml = Buffer.from(String(response.context || ''), 'base64').toString('utf8');
      } catch {}
      requestLog.pushEvent('saml.response', {
        inResponseTo,
        relayState: samlSession.relayState || null,
        acs: response.entityEndpoint,
        samlResponseXml: samlResponseXml ? samlResponseXml.slice(0, 12000) : null,
      });

      if (config.debugSaml) {
        console.log(
          JSON.stringify(
            {
              event: 'saml.login.response',
              inResponseTo,
              relayState: samlSession.relayState || null,
              entityEndpoint: response.entityEndpoint,
              samlResponseLength: response.context ? String(response.context).length : 0,
            },
            null,
            2,
          ),
        );
      }

      req.session.saml = null;

      return res.render('saml-post', response);
    } catch (err) {
      requestLog.pushEvent('saml.login.error', {
        error: String(err && err.stack ? err.stack : err),
      });
      if (config.debugSaml) {
        console.log(
          JSON.stringify(
            {
              event: 'saml.login.error',
              error: String(err && err.stack ? err.stack : err),
            },
            null,
            2,
          ),
        );
      }
      res.status(500);
      return res.render('error', {
        title: '生成 SAMLResponse 失败',
        message: String(err && err.stack ? err.stack : err),
      });
    }
  });

  app.get('/idp/requests', (_req, res) => {
    res.render('requests', {
      items: requestLog.list(),
    });
  });

  app.post('/idp/requests/clear', (_req, res) => {
    requestLog.clear();
    res.redirect('/idp/requests');
  });

  return app;
}

let appPromise = null;
async function getApp() {
  if (!appPromise) appPromise = createApp();
  return appPromise;
}

async function handler(req, res) {
  const app = await getApp();
  return app(req, res);
}

module.exports = {
  createApp,
  handler,
};
