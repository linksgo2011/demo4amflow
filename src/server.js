require('dotenv').config();

const { config } = require('./config');
const { createApp } = require('./app');

createApp()
  .then((app) => {
    app.listen(config.port, () => {
      console.log(`IdP server listening on http://localhost:${config.port}`);
      if (!config.baseUrl) {
        console.log('BASE_URL 未设置，将按请求 Host/Proto 动态计算（建议部署时设置 BASE_URL）');
      }
      if (!config.spMetadataPath && !config.spMetadataXml) {
        console.log('未加载 SP metadata：访问 /idp/sp 进行配置');
      }
    });
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
