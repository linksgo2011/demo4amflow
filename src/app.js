require('dotenv').config();

const saml = require('samlify');
const { validate } = require('@authenio/samlify-xsd-schema-validator');
const express = require('express');
const session = require('express-session');

const { config, resolveBaseUrlFromReq } = require('./config');
const { createRequestLog } = require('./request-log');
const { ensureSigningMaterial } = require('./saml/cert');
const { createIdp } = require('./saml/idp');
const { createSpRegistry } = require('./saml/sp-registry');
const { decodeSamlMaybe } = require('./saml/saml-message');

saml.setSchemaValidator({ validate });

function isVercel() {
  return Boolean(process.env.VERCEL);
}

async function createApp() {
  const app = express();

  app.set('trust proxy', config.trustProxy);
  app.set('view engine', 'ejs');
  app.set('views', `${__dirname}/views`);

  app.use(express.urlencoded({ extended: false, limit: '2mb' }));
  app.use(express.json({ limit: '2mb' }));

  const requestLog = createRequestLog({ max: config.logMax });
  app.use(requestLog.middleware);

  app.use(
    session({
      secret: config.sessionSecret || `dev-${Math.random().toString(16).slice(2)}`,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
      },
    }),
  );

  const allowGenerate = !isVercel();
  const signingMaterial = await ensureSigningMaterial({
    keyPath: config.keyPath,
    certPath: config.certPath,
    commonName: 'demo4amflow-idp',
    privateKeyPem: config.idpPrivateKeyPem,
    certPem: config.idpCertPem,
    allowGenerate,
  });

  const spRegistry = createSpRegistry();
  if (config.spMetadataXml) {
    spRegistry.setFromXml(config.spMetadataXml);
  } else {
    spRegistry.loadFromPath(config.spMetadataPath);
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

  app.get('/', (_req, res) => res.redirect('/idp/info'));

  app.get('/saml/idp/metadata', (req, res) => {
    const { idp } = getIdpContext(req);
    res.type('application/xml');
    res.send(idp.getMetadata());
  });

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

      req.session.saml = {
        binding,
        relayState,
        samlRequestRaw: samlRequestRaw || null,
        requestInfo: parseResult,
        receivedAt: new Date().toISOString(),
      };

      return res.redirect('/idp/login');
    } catch (err) {
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
    const samlSession = req.session.saml || null;
    if (!samlSession) {
      res.status(400);
      return res.render('error', {
        title: '没有待处理的 SAML 请求',
        message: '请从 SP 发起 SSO 请求（AuthnRequest）到 /saml/idp/sso。',
      });
    }

    const extract = samlSession.requestInfo?.extract || null;

    res.render('login', {
      saml: samlSession,
      extract,
      samlRequestDecoded: decodeSamlMaybe(samlSession.samlRequestRaw),
    });
  });

  app.post('/idp/login', async (req, res) => {
    const samlSession = req.session.saml || null;
    if (!samlSession) {
      res.status(400);
      return res.render('error', {
        title: '没有待处理的 SAML 请求',
        message: '会话中未找到 AuthnRequest。请重新从 SP 发起登录。',
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

      req.session.saml = null;

      return res.render('saml-post', response);
    } catch (err) {
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

