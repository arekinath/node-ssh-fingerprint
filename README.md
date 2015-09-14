ssh-fingerprint
===============

Generate or verify a fingerprint given an SSH public key (without `ssh-keygen` or external dependencies)

Install
-------

    npm install ssh-fingerprint

Example
-------

``` js
var fs = require('fs');

var fp = require('ssh-fingerprint');

var publickey = fs.readFileSync('id_rsa.pub', 'utf-8');

console.log('fingerprint => %s',
  fp.calculate(publickey));
console.log('fingerprint => %s',
  fp.calculate(publickey, {algorithm: 'sha256'}));
```

yields

```
fingerprint => 64:c4:c5:c9:7e:91:91:db:e3:35:ca:de:be:84:2e:b0
fingerprint => SHA256:PKBYeRc7Vm0TFSoc4qzRZa4ArOMVvxztziWf6Rh2LHU
```

Usage
-----

### `fingerprint.calculate(pubkey, options);`

Parameters

- `pubkey`: A public key string, typically read from `id_rsa.pub`
- `options`: An object, should contain one or both of the properties:
  - `algorithm`: The hashing algorithm to use, defaults to `md5` (OpenSSH Standard prior to 6.8)
  - `style`: Output format of the fingerprint, choose from `hex` (the old style) or `base64`

The default value for `style` will change to `base64` when using an algorithm other than `md5` -- this mimics the behaviour of `ssh-keygen` in OpenSSH 6.8 and later.

Returns

- The stringified fingerprint, same as `ssh-keygen -E algorithm -fl id_rsa.pub`

### `fingerprint(pubkey, algorithm = 'md5');`

Compatibility alias for `fingerprint.calculate()`.

Parameters

- `pubkey`: A public key string
- `algorithm`: A string name of a hashing algorithm to use, same as `options.algorithm` above

Returns

- The stringified fingerprint, as above

### `fingerprint.verify(pubkey, fingerprint[, algorithms]);`

Verifies whether a given fingerprint matches a particular public key. The comparison is double-hashed, to avoid leaking timing information.

Parameters

- `pubkey`: A public key string, as for `fingerprint.calculate`
- `fingerprint`: A stringified fingerprint, in either the old `hex` format or the new `base64` style
- `algorithms`: Optional Array of algorithms to limit comparisons to (e.g. `['sha256','sha384']`). If the algorithm detected for the given `fingerprint` is not in this list, an `AlgorithmNotEnabled` error is thrown.

Returns

- `true` if the given fingerprint matches the given public key, `false` otherwise

### `fingerprint.verifier(fingerprint[, algorithms]);`

Returns a `verify` function specialised to verifying any given public key against the given fingerprint. This can be used to pre-parse and validate a fingerprint before using the returned function to iterate over available keys to find it.

Parameters:

- `fingerprint`, `algorithms`: as for `fingerprint.verify()` above

Returns

- `func (pubkey)`: a partially evaluated `verify` function

### `fingerprint.FormatNotSupported`

Error subclass thrown by `fingerprint.verify()` when the supplied fingerprint is not in a recognised format.

Properties:

- `fingerprint`: The fingerprint string that failed to parse

### `fingerprint.AlgorithmNotEnabled`

Error subclass thrown by `fingerprint.verify()` when the supplied fingerprint is valid, but uses an algorithm that is not in the given list of enabled algorithms.

Properties:

- `algorithm`: The algorithm used by the fingerprint
- `enabled`: The array of enabled algorithms

### `fingerprint.InvalidAlgorithm`

Error subclass thrown by `fingerprint.verify()` when the supplied fingerprint appears valid, but uses an algorithm that is not supported. The supported algorithm set is kept up to date with OpenSSH, so generally this means that malformed input was provided.

Properties:

- `algorithm`: The algorithm apparently used by the fingerprint

License
-------

MIT
