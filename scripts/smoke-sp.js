const saml = require('samlify');
const { validate } = require('@authenio/samlify-xsd-schema-validator');

saml.setSchemaValidator({ validate });

function buildSpMetadataXml() {
  return `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="http://localhost:4000/sp"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="http://localhost:4000/acs"
      index="1"
      isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`;
}

function extractHiddenInput(html, name) {
  const re = new RegExp(
    `<input[^>]*name=["']${name}["'][^>]*value=["']([^"']*)["'][^>]*>`,
    'i',
  );
  const m = html.match(re);
  return m ? m[1] : null;
}

async function httpRequest(url, { method = 'GET', headers = {}, body, cookie } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  const res = await fetch(url, { method, headers: h, body, redirect: 'manual' });
  const text = await res.text();
  const setCookie = res.headers.get('set-cookie');
  return { res, text, setCookie };
}

function mergeCookie(oldCookie, setCookieHeader) {
  if (!setCookieHeader) return oldCookie || '';
  const first = setCookieHeader.split(',')[0];
  const cookie = first.split(';')[0];
  const merged = new Map();
  for (const part of String(oldCookie || '').split(';')) {
    const p = part.trim();
    if (!p) continue;
    const [k, v] = p.split('=');
    merged.set(k, v);
  }
  const [k, v] = cookie.split('=');
  merged.set(k, v);
  return Array.from(merged.entries())
    .map(([kk, vv]) => `${kk}=${vv}`)
    .join('; ');
}

async function main() {
  const idpBase = 'http://localhost:3000';

  const spMetadataXml = buildSpMetadataXml();
  const sp = saml.ServiceProvider({ metadata: spMetadataXml });

  const idpMetadataXml = await (await fetch(`${idpBase}/saml/idp/metadata`)).text();
  const idp = saml.IdentityProvider({ metadata: idpMetadataXml });

  await fetch(`${idpBase}/idp/sp`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ metadataXml: spMetadataXml }).toString(),
    redirect: 'manual',
  });

  const { context: loginUrl } = sp.createLoginRequest(idp, 'redirect');

  let cookie = '';
  const first = await httpRequest(loginUrl, { cookie });
  cookie = mergeCookie(cookie, first.setCookie);

  if (![301, 302, 303].includes(first.res.status)) {
    console.error('Expected redirect from IdP SSO endpoint, got:', first.res.status);
    const pre = first.text.match(/<pre>([\s\S]*?)<\/pre>/i);
    if (pre) console.error(pre[1].slice(0, 4000));
    else console.error(first.text.slice(0, 2000));
    process.exit(1);
  }

  const location = first.res.headers.get('location');
  if (!location) {
    console.error('Missing Location header');
    process.exit(1);
  }

  const loginPage = await httpRequest(`${idpBase}${location}`, { cookie });
  if (loginPage.res.status !== 200) {
    console.error('Expected login page, got:', loginPage.res.status);
    process.exit(1);
  }

  const state = extractHiddenInput(loginPage.text, 'state');

  const loginPost = await httpRequest(`${idpBase}/idp/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      ...(state ? { state } : {}),
      email: 'test@example.com',
      displayName: 'Test User',
      uid: '10001',
    }).toString(),
    cookie,
  });

  const samlResponse = extractHiddenInput(loginPost.text, 'SAMLResponse');
  if (!samlResponse) {
    console.error('Failed to extract SAMLResponse from HTML');
    console.error(loginPost.text.slice(0, 500));
    process.exit(1);
  }

  const parsed = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse: samlResponse } });
  console.log('OK: parsed SAMLResponse');
  console.log(JSON.stringify(parsed.extract, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
