const saml = require('samlify');

function buildIdpMetadataXml({ entityId, ssoRedirectUrl, ssoPostUrl, certForMetadata }) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="${entityId}"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${certForMetadata}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${ssoRedirectUrl}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${ssoPostUrl}"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
}

function createIdp({ baseUrl, entityId, privateKeyPem, certForMetadata }) {
  const issuer = entityId || `${baseUrl}/saml/idp/metadata`;
  const ssoUrl = `${baseUrl}/saml/idp/sso`;
  const metadata = buildIdpMetadataXml({
    entityId: issuer,
    ssoRedirectUrl: ssoUrl,
    ssoPostUrl: ssoUrl,
    certForMetadata,
  });

  const idp = saml.IdentityProvider({
    metadata,
    privateKey: privateKeyPem,
    isAssertionEncrypted: false,
    nameIDFormat: ['emailAddress', 'persistent', 'transient'],
    loginResponseTemplate: {
      context: saml.SamlLib.defaultLoginResponseTemplate.context,
      attributes: [
        {
          name: 'email',
          nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueXsiType: 'xs:string',
          valueTag: 'email',
        },
        {
          name: 'displayName',
          nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueXsiType: 'xs:string',
          valueTag: 'displayName',
        },
        {
          name: 'uid',
          nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueXsiType: 'xs:string',
          valueTag: 'uid',
        },
      ],
    },
  });

  return { idp, metadata, issuer, ssoUrl };
}

module.exports = { createIdp };
