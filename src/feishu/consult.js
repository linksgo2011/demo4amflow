const { buildAuthorizeUrl } = require('./oauth');

function buildConsultLoginUrl({
  clientId,
  redirectUri,
  scope,
  state,
  passportAppId = '1',
  autoSsoDomain,
}) {
  const authorizeUrl = buildAuthorizeUrl({
    clientId,
    redirectUri,
    scope,
    state,
  });

  const passportUrl = new URL('https://passport.feishu.cn/suite/passport/page/login/');
  passportUrl.searchParams.set('app_id', String(passportAppId));
  passportUrl.searchParams.set('redirect_uri', authorizeUrl);
  if (autoSsoDomain) passportUrl.searchParams.set('auto_sso_domain', String(autoSsoDomain));
  return passportUrl.toString();
}

module.exports = {
  buildConsultLoginUrl,
};

