const path = require('node:path');

function envBool(value, fallback = false) {
  if (value === undefined) return fallback;
  if (value === '1' || value === 'true') return true;
  if (value === '0' || value === 'false') return false;
  return fallback;
}

function envInt(value, fallback) {
  const n = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeBaseUrl(input) {
  if (!input) return null;
  const url = new URL(input);
  return url.toString().replace(/\/$/, '');
}

function resolveBaseUrlFromReq(req) {
  const proto = req.protocol;
  const host = req.get('host');
  return `${proto}://${host}`.replace(/\/$/, '');
}

const config = {
  port: envInt(process.env.PORT, 3000),
  baseUrl: normalizeBaseUrl(process.env.BASE_URL),
  idpEntityId: process.env.IDP_ENTITY_ID || null,
  trustProxy: envBool(process.env.TRUST_PROXY, false),
  sessionSecret: process.env.SESSION_SECRET || null,
  feishuClientId: process.env.FEISHU_CLIENT_ID || null,
  feishuClientSecret: process.env.FEISHU_CLIENT_SECRET || null,
  feishuScope: process.env.FEISHU_SCOPE || null,
  feishuChatId: process.env.FEISHU_CHAT_ID || 'oc_a94917721a99386d176f651cea0cd604',
  feishuVerificationToken: process.env.FEISHU_VERIFICATION_TOKEN || null,
  feishuEncryptKey: process.env.FEISHU_ENCRYPT_KEY || null,
  feishuLongConnection: envBool(process.env.FEISHU_LONG_CONNECTION, false),
  spMetadataPath: process.env.SP_METADATA_PATH || null,
  spMetadataXml: process.env.SP_METADATA_XML || null,
  idpPrivateKeyPem: process.env.IDP_PRIVATE_KEY_PEM || null,
  idpCertPem: process.env.IDP_CERT_PEM || null,
  allowEphemeralCert: envBool(process.env.ALLOW_EPHEMERAL_CERT, false),
  debugSaml: envBool(process.env.DEBUG_SAML, false),
  disableSchemaValidation: envBool(process.env.DISABLE_SCHEMA_VALIDATION, false),
  keyPath: path.resolve(process.env.KEY_PATH || './data/keys/idp.key.pem'),
  certPath: path.resolve(process.env.CERT_PATH || './data/keys/idp.cert.pem'),
  logMax: envInt(process.env.LOG_MAX, 200),
};

module.exports = {
  config,
  resolveBaseUrlFromReq,
};
