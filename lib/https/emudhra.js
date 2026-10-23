var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var forge = require('node-forge');

// Publicly disclosed CA material from mitmproxy commit
// https://github.com/mitmproxy/mitmproxy/commit/169234499088fc2c414644a67efaed3d64ae2e3b
var pem = fs.readFileSync(path.join(__dirname, 'emudhra.pem'), 'utf8');
var privateKey = crypto.createPrivateKey(pem);
var chain = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
var issuerCert = new crypto.X509Certificate(chain[0]);
var asn1 = forge.asn1;
var issuerTbs = asn1.fromDer(forge.pem.decode(chain[0])[0].body).value[0];
var issuerSubject = issuerTbs.value[5];
var extensions = issuerTbs.value[7].value[0].value;
var skiExtension = extensions.filter(function (ext) {
  return asn1.derToOid(ext.value[0].value) === forge.pki.oids.subjectKeyIdentifier;
})[0];
// Use the CA's stored SKI, which need not equal SHA-1 of its public key.
var keyIdentifier = asn1.fromDer(skiExtension.value[skiExtension.value.length - 1].value).value;
var ECDSA_SHA256 = '1.2.840.10045.4.3.2';

module.exports = function (cert) {
  cert.validity.notBefore = new Date(Math.max(
    cert.validity.notBefore.getTime(), Date.parse(issuerCert.validFrom)
  ));
  cert.validity.notAfter = new Date(Math.min(
    cert.validity.notAfter.getTime(), Date.parse(issuerCert.validTo)
  ));
  if (Date.now() >= cert.validity.notAfter.getTime()) {
    throw new Error('The eMudhra intermediate CA certificate has expired');
  }
  cert.setExtensions(cert.extensions.map(function (ext) {
    return ext.name === 'authorityKeyIdentifier'
      ? { name: 'authorityKeyIdentifier', keyIdentifier: keyIdentifier }
      : ext;
  }));
  cert.siginfo.algorithmOid = ECDSA_SHA256;
  var tbs = forge.pki.getTBSCertificate(cert);
  // Forge only signs RSA certificates. ECDSA AlgorithmIdentifier parameters
  // must be absent (RFC 5758), so remove the RSA-style NULL it inserts.
  var algorithm = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
      asn1.oidToDer(ECDSA_SHA256).getBytes())
  ]);
  tbs.value[2] = algorithm;
  tbs.value[3] = issuerSubject;
  // Keep Whistle's RSA leaf key separate from the EC CA signing key.
  var signature = crypto.sign('sha256', Buffer.from(asn1.toDer(tbs).getBytes(), 'binary'), privateKey);
  var certificate = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    tbs,
    algorithm,
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
      String.fromCharCode(0) + signature.toString('binary'))
  ]);
  return forge.pem.encode({ type: 'CERTIFICATE', body: asn1.toDer(certificate).getBytes() })
    + chain.join('\n') + '\n';
};
