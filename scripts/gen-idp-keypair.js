const selfsigned = require('selfsigned');

async function main() {
  const attrs = [{ name: 'commonName', value: 'demo4amflow-idp' }];
  const notBeforeDate = new Date();
  const notAfterDate = new Date();
  notAfterDate.setFullYear(notAfterDate.getFullYear() + 10);

  const pems = await selfsigned.generate(attrs, {
    keySize: 2048,
    algorithm: 'sha256',
    notBeforeDate,
    notAfterDate,
  });

  process.stdout.write('-----BEGIN IDP_PRIVATE_KEY_PEM-----\n');
  process.stdout.write(pems.private.trim());
  process.stdout.write('\n-----END IDP_PRIVATE_KEY_PEM-----\n\n');
  process.stdout.write('-----BEGIN IDP_CERT_PEM-----\n');
  process.stdout.write(pems.cert.trim());
  process.stdout.write('\n-----END IDP_CERT_PEM-----\n');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

