const FEISHU_SP_METADATA_XML = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://www.feishu.cn"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="false"
    WantAssertionsSigned="false">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://www.feishu.cn/suite/passport/authentication/idp/saml/call_back"
      index="1"
      isDefault="true" />
  </SPSSODescriptor>
</EntityDescriptor>`;

module.exports = {
  FEISHU_SP_METADATA_XML,
};

