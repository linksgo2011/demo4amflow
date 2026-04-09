const fs = require('node:fs');
const path = require('node:path');

function readArg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return null;
  return process.argv[idx + 1] || '';
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function usage() {
  const msg = `
用法:
  node scripts/gen-sp-metadata.js --entityId <SP_ENTITY_ID> --acs <ACS_POST_URL> [options]

必填:
  --entityId   SP EntityID（issuer）
  --acs        AssertionConsumerService (HTTP-POST) URL

可选:
  --nameIdFormat <URN>           默认 urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
  --authnRequestsSigned         设置 AuthnRequestsSigned="true"
  --wantAssertionsSigned        设置 WantAssertionsSigned="true"
  --signingCertPemFile <path>   将证书写入 KeyDescriptor(use="signing")，文件应为 PEM(-----BEGIN CERTIFICATE-----)
  --out <path>                  输出到文件（不传则打印到 stdout）

示例:
  node scripts/gen-sp-metadata.js \\
    --entityId "https://sp.example.com/metadata" \\
    --acs "https://sp.example.com/saml/acs"
`;
  console.log(msg.trim());
}

function normalizeX509PemToMetadata(certPem) {
  return String(certPem || '')
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

function buildSpMetadataXml({
  entityId,
  acsPostUrl,
  nameIdFormat,
  authnRequestsSigned,
  wantAssertionsSigned,
  signingCertForMetadata,
}) {
  const keySection = signingCertForMetadata
    ? `
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${signingCertForMetadata}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>`
    : '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="${entityId}"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="${authnRequestsSigned ? 'true' : 'false'}"
    WantAssertionsSigned="${wantAssertionsSigned ? 'true' : 'false'}">
    ${keySection.trimStart()}
    <NameIDFormat>${nameIdFormat}</NameIDFormat>
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsPostUrl}"
      index="1"
      isDefault="true" />
  </SPSSODescriptor>
</EntityDescriptor>`;
}

function main() {
  if (hasFlag('--help') || hasFlag('-h')) {
    usage();
    process.exit(0);
  }

  const entityId = readArg('--entityId');
  const acsPostUrl = readArg('--acs');
  const outPath = readArg('--out');
  const signingCertPemFile = readArg('--signingCertPemFile');

  if (!entityId || !acsPostUrl) {
    usage();
    process.exit(1);
  }

  const nameIdFormat =
    readArg('--nameIdFormat') ||
    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

  let signingCertForMetadata = null;
  if (signingCertPemFile) {
    const pem = fs.readFileSync(path.resolve(signingCertPemFile), 'utf8');
    signingCertForMetadata = normalizeX509PemToMetadata(pem);
  }

  const xml = buildSpMetadataXml({
    entityId,
    acsPostUrl,
    nameIdFormat,
    authnRequestsSigned: hasFlag('--authnRequestsSigned'),
    wantAssertionsSigned: hasFlag('--wantAssertionsSigned'),
    signingCertForMetadata,
  });

  if (outPath) {
    fs.writeFileSync(path.resolve(outPath), xml, 'utf8');
    console.log(`OK: wrote ${outPath}`);
    return;
  }

  process.stdout.write(xml);
}

main();

