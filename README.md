# 飞书群聊 Demo 参考代码

本 Demo 已经包含功能：

- SSO：使用自有 IDP 进行单点登录飞书
- 飞书群聊 UI：通过指定群聊 ID 以用户身份发送消息到群聊, 获取群聊记录
- 调用 Aily 知识库 API 实现问答

本 Demo 未包含的功能（需要补充 PoC）：

- 通过 API 创建人员
- 通过 API 加入群聊
- 接收飞书事件
- 更美观和完善的聊天 UI 和收发消息
- @群机器人，机器人调用 Aily 知识库实现问答
- 嵌入本 Demo 到 PRM APP
- 将以上能力串起来，构建完整的飞书群聊功能

要实现飞书群聊，需要用户完成 SSO 登陆 + 授权，才能使用用户身份的 API 发送消息。

基于 API 群聊 Demo 效果参考下面的视频：

<video width="640" height="360" controls>
  <source src="聊天 demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>


调用飞书 Aily 智能问答 Demo 效果参考下面的视频：

<video width="640" height="360" controls>
  <source src="智能问答 demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

## 飞书 SSO 配置集成注意事项（躺过的坑，非常重要，否则 SSO 很难配置成功）

- 开启 SSO 单点登录需要 商业旗舰版，在 安全-> 账号安全中开启
- 飞书 SSO 配置断言中需要使用 email 关联用户，IDP 使用 email 登陆后，飞书会寻找通讯录中中配置了同样的 email 的用户进行登陆
- 由于群聊集成在 PRM 中，因此 PRM 是 IDP，飞书是 SP 角色，了解什么是 IDP 参考 https://www.cloudflare.com/learning/access-management/what-is-an-identity-provider/
- 本服务启动后访问 /idp/info 可以获取到飞书配置 IDP 的信息
    - IdP Issuer (entityID)： {BaseURL}/saml/idp/metadata
    - IdP Metadata URL： {BaseURL}/saml/idp/metadata
    - IdP Sign-on URL： {BaseURL}/saml/idp/sso
- 选择/开启“验签”时，按 “Response 签名（SAMLResponse 签名）” 来配置，证书信息可以在 /idp/info 页面中 SAML 证书（PEM）获取到，只需要填入正文不需要 BEGIN CERTIFICATE 头尾。
- 飞书 SSO 和授权流程：用户点击聊天 -> 进入 SSO 登录页 -> 输入用户名和密码 -> 登录成功后，跳转到聊天应用 -> 发起用户授权 -> 用户同意授权后，跳转回聊天应用，开始聊天。由于飞书技术限制 SSO 登陆成功后，不允许跳转回聊天应用，所以和飞书技术人员沟通后采用折中方案：将授权页作为 SSO 跳转页面，SSO 成功后直接进入授权页，用户授权后，利用授权页的回调地址，跳转到聊天应用落地页。
- 之前尝试将 Demo 部署到 vercel.app，但飞书无法发送事件到 vercel.app 上，因此无法测试接受消息的能力，注意将 vercel.app 部署到国内的服务器
- SSO 发起拼接例子：https://accounts.feishu.cn/accounts/page/login?app_id=1&no_trap=1&redirect_uri=https%3A%2F%2Faccounts.feishu.cn%2Fopen-apis%2Fauthen%2Fv1%2Fauthorize%3Fclient_id%3Dcli_a95de875f6f95bc0%26redirect_uri%3Dhttps%253A%252F%252Fdemo4amflow.vercel.app%252Fchat%252Fcallback%26response_type%3Dcode%26scope%3Dim%253Amessage%253Areadonly%2Bim%253Amessage%2Bim%253Amessage.group_msg%2Bim%253Amessage.group_msg%253Aget_as_user%2Bim%253Amessage.send_as_user%2Bim%253Amessage%253Asend_as_bot%2Boffline_access%26state%3DeyJyZWRpcmVjdFVyaSI6Imh0dHBzOi8vZGVtbzRhbWZsb3cudmVyY2VsLmFwcC9jaGF0L2NhbGxiYWNrIiwiYXQiOjE3NzYzMDU2OTY2NzEsImlhdCI6MTc3NjMwNTY5NiwiZXhwIjoxNzc2MzkyMDk2fQ.6Xq8ewpq9-hWU6NndIJJUTSSDkuVVjiYx9c27HwVnj4

## 调用 Aily 知识库 API 实现问答注意事项（躺过的坑，非常重要）

- 飞书 Aily 是一个相对飞书办公套件独立的模块
- 可以通过 Aily Agent/工作流应用两种方式创建 Agent，这两种方式创建的 Agent 都能被加入到机器人，但只有工作流应用创建的 Agent 才能通过 API 调用，工作流能够通过画布构建复杂的逻辑，实现更高级的功能。
- 通过工作流创建的应用会在**飞书开发者后台（不是 Aily 开发者后台）**中同步一个应用，可以开启机器人功能。注意：调用飞书 Aily 的 API 需要使用 Aily 创建的应用 ID 和 secret。（注意区分上面用于聊天的应用 ID 和 secret）
- 飞书 Aily 提供了：执行知识问答、多轮对话、调用技能三套 API，都能实现知识问答。
  - 执行知识问答：已经被弃用，验证调用无结果
  - 多轮对话：需要开启一个 session 不太适合我们自己管理上下文的场景
  - 调用技能：需要在工作流中配置技能，才能调用，需要传入技能 ID
- 工作流应用需要配置输入和输出参数，才能正确调用调用技能接口‘

## 其他注意事项

- 聊天文档中是以应用的身份发消息，是因为文档没更新，功能已经具备，使用 user_access_token 凭证代替 tenant_access_token 即可使用用户身份发消息
- 使用 chat_id 标识群聊, 使用固定：oc_a94917721a99386d176f651cea0cd604

## 参考文档

- 获取群聊的历史记录 https://open.feishu.cn/document/server-docs/im-v1/message/list?appId=cli_a95eca6f2a785cc3
- 在群聊中发送消息 https://open.feishu.cn/document/server-docs/im-v1/message/create
- 接收群聊消息 https://open.feishu.cn/document/server-docs/im-v1/message/events/receive
- 飞书授权文档 https://open.feishu.cn/document/authentication-management/access-token/obtain-oauth-code
- 获取用户 access_token 文档 https://open.feishu.cn/document/authentication-management/access-token/get-user-access-token
