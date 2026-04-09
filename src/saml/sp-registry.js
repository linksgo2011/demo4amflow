const fs = require('node:fs');
const saml = require('samlify');

function readIfExists(p) {
  if (!p) return null;
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return null;
  }
}

function createSpRegistry() {
  let current = null;

  function get() {
    return current;
  }

  function setFromXml(metadataXml) {
    const sp = saml.ServiceProvider({ metadata: metadataXml });
    current = {
      metadataXml,
      sp,
      entityId: sp.entityMeta.getEntityID(),
    };
    return current;
  }

  function loadFromPath(filePath) {
    const xml = readIfExists(filePath);
    if (!xml) return null;
    return setFromXml(xml);
  }

  return { get, setFromXml, loadFromPath };
}

module.exports = { createSpRegistry };
