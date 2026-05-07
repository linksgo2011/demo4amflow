const { refreshUserAccessToken } = require('./oauth');
const { getCookie, verifyTokenCookie } = require('./token-cookie');

const FEISHU_UAT_COOKIE = 'feishu_uat';
const FEISHU_RT_COOKIE = 'feishu_rt';

function msUntilExpiry(sessionFeishu) {
  const expiresIn = Number(sessionFeishu?.expiresIn || 0);
  const obtainedAt = sessionFeishu?.obtainedAt ? Date.parse(sessionFeishu.obtainedAt) : 0;
  if (!expiresIn || !obtainedAt) return null;
  return obtainedAt + expiresIn * 1000 - Date.now();
}

function ensureTokensFromCookies(req, sessionSecret) {
  if (!req.session) return;

  const sessionFeishu = req.session.feishu || {};

  if (!sessionFeishu.userAccessToken) {
    const cookieValue = getCookie(req, FEISHU_UAT_COOKIE);
    const verified = verifyTokenCookie(cookieValue, sessionSecret);
    if (verified.ok) sessionFeishu.userAccessToken = verified.token;
  }

  if (!sessionFeishu.refreshToken) {
    const cookieValue = getCookie(req, FEISHU_RT_COOKIE);
    const verified = verifyTokenCookie(cookieValue, sessionSecret);
    if (verified.ok) sessionFeishu.refreshToken = verified.token;
  }

  req.session.feishu = sessionFeishu;
}

async function getUserAccessToken(req, config, sessionSecret) {
  ensureTokensFromCookies(req, sessionSecret);

  const sessionFeishu = req.session?.feishu || null;
  const token = sessionFeishu?.userAccessToken || null;
  if (!token) return null;

  const leftMs = msUntilExpiry(sessionFeishu);
  if (leftMs === null) return token;
  if (leftMs > 60 * 1000) return token;

  const refreshToken = sessionFeishu?.refreshToken || null;
  if (!refreshToken) return token;
  if (!config.feishuClientId || !config.feishuClientSecret) return token;

  const tokenResp = await refreshUserAccessToken({
    clientId: config.feishuClientId,
    clientSecret: config.feishuClientSecret,
    refreshToken,
  });
  const data = tokenResp.data || tokenResp;
  const newAccessToken = data.access_token || null;
  if (!newAccessToken) return token;

  req.session.feishu = {
    ...(req.session.feishu || {}),
    userAccessToken: newAccessToken,
    refreshToken: data.refresh_token || null,
    expiresIn: data.expires_in || null,
    refreshTokenExpiresIn: data.refresh_token_expires_in || null,
    scope: data.scope || null,
    tokenType: data.token_type || null,
    obtainedAt: new Date().toISOString(),
  };

  return newAccessToken;
}

module.exports = {
  getUserAccessToken,
  ensureTokensFromCookies,
};

