var crypto = require('crypto');
var assert = require('assert');

var pubre = /^(ssh-[dr]s[as]\s+)|(\s+.+)|\n/g;

/* So you can var f = require('ssh-fingerprint'); f(...) */
module.exports = fingerprint;
fingerprint.calculate = calculate;
fingerprint.verify = verify;
fingerprint.FormatNotSupported = FormatNotSupported;
fingerprint.AlgorithmNotEnabled = AlgorithmNotEnabled;

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

function fingerprint(pub, alg) {
  if (typeof (alg) !== 'string')
    throw (new TypeError('Expected string as second argument, ' +
      'got a ' + typeof (alg) + ' instead'));
  return (calculate(pub, {algorithm: alg}));
}

function calculate(pub, opts) {
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

  var cleanpub = pub.replace(pubre, '');
  var pubbuffer = new Buffer(cleanpub, 'base64');
  var key = hash(pubbuffer, alg, style);

  return key;
}

function verify(pub, fp, algs) {
  var alg, hash;
  assert(typeof (fp) === 'string');

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

  var cleanpub = pub.replace(pubre, '');
  var pubbuffer = new Buffer(cleanpub, 'base64');
  var pubhash = crypto.createHash(alg).update(pubbuffer).digest();

  /* Double-hash to avoid leaking any timing information */
  var hash2 = crypto.createHash(alg).update(hash).digest('base64');
  var pubhash2 = crypto.createHash(alg).update(pubhash).digest('base64');

  return (hash2 === pubhash2);
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
