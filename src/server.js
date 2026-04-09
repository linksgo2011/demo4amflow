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
        console.log('未设置 SP metadata：已使用内置默认 SP（如需覆盖：设置 SP_METADATA_XML 或访问 /idp/sp 保存）');
      }
    });
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
