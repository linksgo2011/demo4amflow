# 飞书群聊 Demo 参考代码

本 Demo 包含功能

- SSO：使用自有 IDP 进行单点登录飞书
- 飞书群聊 UI：通过指定群聊 ID 以用户身份发送消息到群聊, 获取群聊记录

要实现飞书群聊，需要用户完成 SSO 登陆 + 授权，才能使用用户身份的 API 发送消息。

Demo 效果参考下面的视频：

<video width="640" height="360" controls>
  <source src="demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

## 飞书 SSO 配置集成注意事项

- 开启 SSO 单点登录需要 商业旗舰版，在 安全-> 账号安全中开启
- 由于群聊集成在 PRM 中，因此 PRM 是 IDP，飞书是 SP 角色，了解什么是 IDP 参考 https://www.cloudflare.com/learning/access-management/what-is-an-identity-provider/
- 本服务启动后访问 /idp/info 可以获取到飞书配置 IDP 的信息
    - IdP Issuer (entityID)： {BaseURL}/saml/idp/metadata
    - IdP Metadata URL： {BaseURL}/saml/idp/metadata
    - IdP Sign-on URL： {BaseURL}/saml/idp/sso
- 选择/开启“验签”时，按 “Response 签名（SAMLResponse 签名）” 来配置，证书信息可以在 /idp/info 页面中 SAML 证书（PEM）获取到，只需要填入正文不需要 BEGIN CERTIFICATE 头尾。



