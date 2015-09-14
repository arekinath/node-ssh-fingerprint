var crypto = require('crypto');
var assert = require('assert-plus');

var pubre = /^(ssh-[dr]s[as]\s+)|(\s+.+)|\n/g;

/* So you can var f = require('ssh-fingerprint'); f(...) */
module.exports = fingerprint;
fingerprint.calculate = calculate;
fingerprint.verify = verify;
fingerprint.verifier = verifier;
fingerprint.FormatNotSupported = FormatNotSupported;
fingerprint.AlgorithmNotEnabled = AlgorithmNotEnabled;
fingerprint.InvalidAlgorithm = InvalidAlgorithm;

function FormatNotSupported(fp) {
  this.name = 'FormatNotSupported';
  this.fingerprint = fp;
  this.message = 'Fingerprint format is not supported, or is invalid';
}
FormatNotSupported.prototype = Error.prototype;

function AlgorithmNotEnabled(alg, avalgs) {
  this.name = 'AlgorithmNotEnabled';
  this.algorithm = alg
  this.enabled = avalgs;
  this.message = 'Fingerprint supplied uses an algorithm (' + alg + ') ' +
    'that was not listed in the enabled algorithms';
}
AlgorithmNotEnabled.prototype = Error.prototype;

function InvalidAlgorithm(alg) {
  this.name = 'InvalidAlgorithm';
  this.algorithm = alg
  this.message = 'Fingerprint supplied uses an algorithm (' + alg + ') ' +
    'that is invalid or not supported for use with SSH keys';
}
InvalidAlgorithm.prototype = Error.prototype;

var opensshHashAlgos = {
  'md5': true,
  'sha1': true,
  'sha256': true,
  'sha384': true,
  'sha512': true
};

function fingerprint(pub, alg) {
  if (typeof (alg) !== 'string')
    throw (new TypeError('Expected string as second argument, ' +
      'got a ' + typeof (alg) + ' instead'));
  return (calculate(pub, {algorithm: alg}));
}

function calculate(pub, opts) {
  assert.string(pub, 'publickey');
  if (typeof(opts) !== 'object')
    throw (new TypeError('Expected object as second argument, ' +
      'got a ' + typeof (opts) + ' instead'));

  var alg = opts.algorithm;
  var style = opts.style;

  alg = alg || 'md5'; // OpenSSH Standard
  if (style === undefined)
    if (alg === 'md5')
      style = 'hex';
    else
      style = 'base64';
  assert.string(alg, 'algorithm');
  assert.string(style, 'style');

  if (opensshHashAlgos[alg.toLowerCase()] !== true)
    throw (new InvalidAlgorithm(alg));

  var cleanpub = pub.replace(pubre, '');
  var pubbuffer = new Buffer(cleanpub, 'base64');
  var key = hash(pubbuffer, alg, style);

  return key;
}

function verifier(fp, algs) {
  var alg, hash;
  assert.string(fp, 'fingerprint');
  assert.optionalArrayOfString(algs, 'algorithms');

  var parts = fp.split(':');
  if (parts.length == 2) {
    alg = parts[0];
    hash = new Buffer(parts[1], 'base64');
  } else if (parts.length > 2) {
    alg = 'md5';
    if (parts[0].toLowerCase() === 'md5')
      parts = parts.slice(1);
    parts = parts.join('');
    if (!/^[a-fA-F0-9]+$/.test(parts))
      throw (new Error('Fingerprint contains invalid hex characters'));
    hash = new Buffer(parts, 'hex');
  }

  if (alg === undefined)
    throw (new FormatNotSupported(fp));

  if (algs !== undefined) {
    algs = algs.map(function (a) { return a.toLowerCase(); });
    if (algs.indexOf(alg.toLowerCase()) === -1)
      throw (new AlgorithmNotEnabled(alg, algs));
  }

  if (opensshHashAlgos[alg.toLowerCase()] !== true)
    throw (new InvalidAlgorithm(alg));

  var hash2 = crypto.createHash(alg).update(hash).digest('base64');

  function verif(pub) {
    assert.string(pub, 'pubkey');

    var cleanpub = pub.replace(pubre, '');
    var pubbuffer = new Buffer(cleanpub, 'base64');
    var pubhash = crypto.createHash(alg).update(pubbuffer).digest();

    /* Double-hash to avoid leaking any timing information */
    var pubhash2 = crypto.createHash(alg).update(pubhash).digest('base64');

    return (hash2 === pubhash2);
  }

  return (verif);
}

function verify(pub, fp, algs) {
  var verif = verifier(fp, algs);
  return (verif(pub));
}

// hash a string with the given alg
function hash(s, alg, style) {
  var h = crypto.createHash(alg).update(s);
  if (style === 'hex')
    return colons(h.digest('hex'));
  else if (style === 'base64')
    return sshBase64Format(alg, h);
  else
    throw (new Error('Unknown hash style: ' + style));
}

function sshBase64Format(alg, h) {
  return alg.toUpperCase() + ':' + base64Strip(h.digest('base64'));
}

// add colons, 'hello' => 'he:ll:o'
function colons(s) {
  return s.replace(/(.{2})(?=.)/g, '$1:');
}

// strip trailing = on base64-encoded payload
function base64Strip(s) {
  return s.replace(/=*$/, '');
}
