const zlib = require('node:zlib');

function base64ToBuffer(b64) {
  return Buffer.from(String(b64 || ''), 'base64');
}

function decodeSamlMaybe(raw) {
  if (!raw) return null;
  const input = String(raw);

  try {
    const buf = base64ToBuffer(input);
    if (!buf.length) return null;

    try {
      const inflated = zlib.inflateRawSync(buf);
      const xml = inflated.toString('utf8');
      if (xml.includes('<')) return { xml, encoding: 'base64+deflate' };
    } catch {
      const xml = buf.toString('utf8');
      if (xml.includes('<')) return { xml, encoding: 'base64' };
    }

    return { xml: buf.toString('utf8'), encoding: 'base64' };
  } catch {
    return null;
  }
}

module.exports = { decodeSamlMaybe };
