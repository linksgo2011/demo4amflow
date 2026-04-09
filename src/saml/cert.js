const fs = require('node:fs');
const path = require('node:path');
const selfsigned = require('selfsigned');

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function readIfExists(p) {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return null;
  }
}

function writeFileAtomic(filePath, contents) {
  const dir = path.dirname(filePath);
  ensureDir(dir);
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, contents, 'utf8');
  fs.renameSync(tmp, filePath);
}

function normalizeX509PemToMetadata(certPem) {
  return String(certPem || '')
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

async function ensureSigningMaterial({
  keyPath,
  certPath,
  commonName,
  privateKeyPem: providedPrivateKeyPem,
  certPem: providedCertPem,
  allowGenerate = true,
}) {
  if (providedPrivateKeyPem && providedCertPem) {
    return {
      privateKeyPem: providedPrivateKeyPem,
      certPem: providedCertPem,
      certForMetadata: normalizeX509PemToMetadata(providedCertPem),
      generated: false,
    };
  }

  const existingKey = readIfExists(keyPath);
  const existingCert = readIfExists(certPath);
  if (existingKey && existingCert) {
    return {
      privateKeyPem: existingKey,
      certPem: existingCert,
      certForMetadata: normalizeX509PemToMetadata(existingCert),
      generated: false,
    };
  }

  if (!allowGenerate) {
    throw new Error('ERR_MISSING_IDP_SIGNING_MATERIAL');
  }

  const attrs = [{ name: 'commonName', value: commonName || 'saml-idp' }];
  const notBeforeDate = new Date();
  const notAfterDate = new Date();
  notAfterDate.setFullYear(notAfterDate.getFullYear() + 10);

  const pems = await selfsigned.generate(attrs, {
    keySize: 2048,
    algorithm: 'sha256',
    notBeforeDate,
    notAfterDate,
  });

  writeFileAtomic(keyPath, pems.private);
  writeFileAtomic(certPath, pems.cert);

  return {
    privateKeyPem: pems.private,
    certPem: pems.cert,
    certForMetadata: normalizeX509PemToMetadata(pems.cert),
    generated: true,
  };
}

module.exports = {
  ensureSigningMaterial,
  normalizeX509PemToMetadata,
};
