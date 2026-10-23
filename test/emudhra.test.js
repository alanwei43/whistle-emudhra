/*eslint no-console: "off"*/
var assert = require('assert');
var cp = require('child_process');
var crypto = require('crypto');
var fs = require('fs');
var http = require('http');
var os = require('os');
var path = require('path');
var tls = require('tls');

var mode = process.argv[2];

function readAsset(name) {
  return fs.readFileSync(path.join(__dirname, 'assets/certs', name), 'utf8');
}

function getChain(pem) {
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)
    .map(function (cert) { return new crypto.X509Certificate(cert); });
}

function handshake(pair, hostname, ca, sniCallback, shouldFail) {
  return new Promise(function (resolve, reject) {
    var server = tls.createServer({
      key: pair.key,
      cert: pair.cert,
      SNICallback: sniCallback
    }, function (socket) { socket.end(); });
    server.on('tlsClientError', function () {});
    server.on('error', reject);
    server.listen(0, '127.0.0.1', function () {
      var client = tls.connect({
        host: '127.0.0.1',
        port: server.address().port,
        servername: hostname,
        ca: ca,
        rejectUnauthorized: true
      });
      client.setTimeout(5000, function () {
        client.destroy(new Error('TLS handshake timed out'));
      });
      client.on('secureConnect', function () {
        try {
          assert(!shouldFail, 'an unrelated CA must not authorize the certificate');
          assert(client.authorized, 'TLS chain and hostname must be verified');
        } catch (err) {
          reject(err);
        }
      });
      client.on('error', function (err) {
        if (!shouldFail || err.code !== 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY') {
          reject(err);
        }
      });
      client.on('close', function () { server.close(resolve); });
    });
  });
}

async function checkCertificates(enabled) {
  var config = require('../lib/config');
  config.extend({ emudhra: enabled, rcPath: 'none' });
  assert.strictEqual(!!config.emudhra, enabled);
  var ca = require('../lib/https/ca');
  var root = ca.getRootCA();
  var rootFile = fs.readFileSync(ca.getRootCAFile(), 'utf8');
  assert.strictEqual(root.cert, rootFile);
  var rootCert = new crypto.X509Certificate(root.cert);
  var trustedRoot = enabled ? readAsset('emsign-ecc-root-g3.crt') : root.cert;
  var names = ['example.test', '*.wildcard.test', '127.0.0.1', '::1'];
  names.forEach(function (name) {
    var pair = ca.createCertificate(name);
    var chain = getChain(pair.cert);
    var leaf = chain[0];
    assert.strictEqual(chain.length, enabled ? 3 : 1);
    assert(leaf.checkPrivateKey(crypto.createPrivateKey(pair.key)));
    assert(leaf.verify(enabled ? chain[1].publicKey : rootCert.publicKey));
    assert(!leaf.ca, 'generated certificates must not be CAs');
    if (name === '127.0.0.1' || name === '::1') {
      assert(leaf.checkIP(name), 'IP SAN must be preserved');
    } else {
      assert(leaf.checkHost(name === '*.wildcard.test' ? 'www.wildcard.test' : name));
    }
    if (enabled) {
      assert.strictEqual(chain[1].publicKey.asymmetricKeyType, 'ec');
      assert(leaf.checkIssued(chain[1]), 'issuer and AKI must match the intermediate CA');
      assert(chain[1].verify(chain[2].publicKey));
      assert(chain[2].verify(new crypto.X509Certificate(trustedRoot).publicKey));
      var forge = require('node-forge');
      var parsed = forge.pki.certificateFromPem(pair.cert);
      var asn1 = forge.asn1;
      var aki = asn1.fromDer(parsed.getExtension('authorityKeyIdentifier').value).value[0].value;
      assert.strictEqual(forge.util.bytesToHex(aki), '34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c');
      var der = asn1.fromDer(forge.pem.decode(pair.cert)[0].body);
      assert.strictEqual(der.value[0].value[2].value.length, 1);
      assert.strictEqual(der.value[1].value.length, 1);
    }
    tls.createSecureContext(pair);
  });
  var cached = ca.serverAgent.createCertificate('cached.test');
  assert.strictEqual(ca.serverAgent.createCertificate('cached.test'), cached);
  assert.strictEqual(ca.createCertificate('cached.test'), cached);
  var pair = ca.createCertificate('example.test');
  await handshake(pair, 'example.test', trustedRoot, ca.SNICallback);
  // Exercise wildcard selection through the actual SNI callback.
  await handshake(pair, 'www.wildcard.test', trustedRoot, ca.SNICallback);
  if (enabled) {
    await handshake(pair, 'example.test', root.cert, ca.SNICallback, true);
  }
  var custom = {
    key: readAsset('test.key'),
    cert: readAsset('test.crt')
  };
  ca.uploadCerts({ custom: custom });
  assert.strictEqual(ca.serverAgent.createCertificate('www.test.whistlejs.com').cert, custom.cert);
  var remote = { key: pair.key, cert: pair.cert };
  ca.remoteCerts.set('remote.test', remote);
  assert.strictEqual(ca.serverAgent.createCertificate('remote.test'), remote);
  assert.strictEqual(fs.readFileSync(ca.getRootCAFile(), 'utf8'), rootFile);
  assert.strictEqual(ca.getRootCA().key, root.key);
}

function checkCli(command) {
  var starting = require('starting');
  var called = false;
  starting.cli[command] = function (main, options) {
    called = true;
    assert.strictEqual(options.emudhra, true);
    assert.strictEqual(options.port, '12345');
  };
  process.argv = [process.execPath, path.join(__dirname, '../bin/whistle.js'),
    command, '--emudhra', '--port', '12345'];
  require('../bin/whistle');
  assert(called, 'CLI command must receive the parsed options');
}

function checkProxy() {
  return new Promise(function (resolve, reject) {
    var upstream = http.createServer(function (req, res) { res.end('emudhra CONNECT ok'); });
    var server = http.createServer();
    upstream.on('error', reject);
    server.on('error', reject);
    upstream.listen(0, '127.0.0.1', function () {
      server.listen(0, '127.0.0.1', function () {
        require('../index')({
          server: server,
          emudhra: true,
          debugMode: true,
          inspect: true, // Keep service helpers in this test process.
          rcPath: 'none',
          mode: 'capture|disableUpdateTips',
          shadowRules: 'proxy.test http://127.0.0.1:' + upstream.address().port
        }, function () {
          var req = http.request({
            host: '127.0.0.1', port: server.address().port,
            method: 'CONNECT', path: 'proxy.test:443'
          });
          req.on('error', reject);
          req.on('connect', function (res, socket) {
            if (res.statusCode !== 200) {
              return reject(new Error('CONNECT failed: ' + res.statusCode));
            }
            var client = tls.connect({
              socket: socket,
              servername: 'proxy.test',
              ca: readAsset('emsign-ecc-root-g3.crt'),
              rejectUnauthorized: true
            }, function () {
              client.write('GET / HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n');
            });
            var body = '';
            client.on('error', reject);
            client.on('data', function (data) {
              body += data;
              if (body.indexOf('emudhra CONNECT ok') === -1) {
                return;
              }
              try {
                assert(client.authorized);
                assert(/^HTTP\/1\.1 200 /.test(body));
                client.destroy();
                resolve();
              } catch (err) {
                reject(err);
              }
            });
          });
          req.end();
        });
      });
    });
  });
}

if (mode) {
  Promise.resolve().then(function () {
    if (mode === 'proxy') {
      return checkProxy();
    }
    return mode.indexOf('cli-') === 0
      ? checkCli(mode.substring(4))
      : checkCertificates(mode === 'emudhra');
  }).then(function () {
    process.exit(0);
  }).catch(function (err) {
    console.error(err.stack);
    process.exit(1);
  });
} else {
  var tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'whistle-emudhra-test-'));
  var savedRoot;
  try {
    ['cli-run', 'cli-start', 'cli-restart', 'default', 'emudhra', 'default', 'proxy'].forEach(function (name) {
      cp.execFileSync(process.execPath, [__filename, name], {
        env: Object.assign({}, process.env, { WHISTLE_PATH: tempDir }),
        stdio: 'pipe',
        timeout: 20000
      });
      if (name.indexOf('cli-') !== 0) {
        var root = ['root.key', 'root.crt'].map(function (filename) {
          return fs.readFileSync(path.join(tempDir, '.whistle/certs', filename), 'utf8');
        });
        if (savedRoot) {
          assert.deepStrictEqual(root, savedRoot, 'switching signers must preserve the local root CA');
        }
        savedRoot = root;
      }
      console.log('Passed: ' + name);
    });
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}
