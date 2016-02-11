{KeyManager} = require '../..'
{bufeq_secure} = require '../../lib/util'

#============================================================================


key_without_cross_sig = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase Go 1.0.10 (darwin)
Comment: https://keybase.io/download

xo0EVr0A8wEEAOouu6kTiwMFfHJ2ZoTiEpOSPxMbUSPowGouDkVYBWCbzMXLMKbX
84YCQIihsaVvRUTBbdobhO8qD3CFsGWPodmmwjdYYDCGs+KVlH49QfHXjH5epItG
RG8lel+QpOmGQa1vhOdRorgXz0ROwzJzgAk3qUl/Fm8BUKuxQmXopTBHABEBAAHN
I1Rlc3QgNiBLZXkgPHRoZW1heCt0ZXN0NkBnbWFpbC5jb20+wrIEEwECACYFAla9
APMJEBXWxhRRsg4TAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQAAMUoEAN5pYfC5DSfB
eYUtMIyzPPQihrJBdONRL8wjDn0d5vAAERddxYhL1OxbsGwQIjNI2EWxbk6vKh3/
qNZiQKqYNavI9V9YBrbVNJ8D6eQpZJogpDDe3WkjfzPKg61vwUFOF2XzcYKHrngg
98Y1ag2w2HiPC1GmgIYyPC116IpIMLOpzo0EVr0A8wEEAKeEhup41f4lN3kG6Mps
959rQturGGbsWD2fCXQ/ryoqkBuGcR7lnmR8UP3NIVIVBGh9kov59njH+4D+/SJ0
Oj4VgDW0rn4EYbenSrDSWaNf9I5mgA8+G/DsaICdsUYf8D2EUWDviKqhh3mSRSoG
jfqWVkxsTTd+E3CE1spjEDg3ABEBAAHCnwQYAQIAEwUCVr0A8wkQFdbGFFGyDhMC
GwwAAAqpBAAPy9cwVyTdEpu34r+284Oq2y11LEBO/TNMUWqztqrxBn8iefBOIUgV
ktbnW1i/H9XFJPhxgF9wGa6hLJYuvfRG3GtSOQixz/oS4jMlwAGK2MmVvTsZi/lg
ulpZAoZk6zMfJRm3BkFhhkp7AB5Okg1pceGikNYOCHcm02okzZO/B86NBFa9AQAB
BACYwrQl6PrgFn5hK+Ue8a7ljXKgMPpk2HpF+cFIL0KM+/JphWrfsSN1EUpVJOBD
DTRAksSA1y+B4X3TuJb1qYey2lBnaB7gUtqrWYmrkottpygT7hZar8JntRsQrvKF
DjFdgJg+/NEi7doGYmkRVA/JIQSqroswgVxZEVPVlZvzZQARAQABwp8EGAECABMF
Ala9AQAJEBXWxhRRsg4TAhsCAABkGgQAEn3sYIiafWr1xg/8TBPd3lFgFAlJnZ84
8gIZx9RGy5AhcbGLq9EezZW8+tHAjFcWL7Ex1bg4dqApoA6SJFfHhxlkNyM9Vrnn
DJVpsnGhwVufOT6SpyDbV31iDVhTSK6jY/EIcW/YDnMguf0Ybexsjv7Er66gygO3
SfvXjnAewcg=
=So85
-----END PGP PUBLIC KEY BLOCK-----"""

key_with_cross_sig = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

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
tmIuHu1WeYgLy8ZUju/jcJcb9XYI6rBP
=YFA2
-----END PGP PUBLIC KEY BLOCK-----
"""

count_subkeys = (km) ->
  n = 0
  km = km.pgp
  n++ for i in km.subkeys when not km.key(i).is_revoked()
  n

exports.test_subkey_without_cross_sig = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key_without_cross_sig, opts : { strict : true } }, defer err, km, warnings
  T.no_error err
  T.assert count_subkeys(km) is 1
  T.assert warnings.warnings().length is 1
  T.equal warnings.warnings()[0], "Subkey 1 was invalid; discarding"
  k = km.find_verifying_pgp_key()
  wanted = new Buffer ("36A9 F360 387A 32F8 4D78  C18D 15D6 C614 51B2 0E13".split(/\s+/).join('')), 'hex'
  T.assert bufeq_secure wanted, k.get_fingerprint()
  cb()

exports.test_subkey_with_cross_sig = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key_with_cross_sig, opts : { strict : true } }, defer err, km, warnings
  T.no_error err
  T.assert count_subkeys(km) is 2
  T.assert warnings.warnings().length is 0
  k = km.find_verifying_pgp_key()
  wanted = new Buffer ("FCFF 7A50 95B7 29EF F05D  846C E243 596D 5865 D60F".split(/\s+/).join('')), 'hex'
  T.assert bufeq_secure wanted, k.get_fingerprint()
  cb()


