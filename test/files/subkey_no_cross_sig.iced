{KeyManager} = require '../..'

#============================================================================


key = """-----BEGIN PGP PUBLIC KEY BLOCK-----
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

exports.test_subkey_without_cross_sig = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km, warnings
  T.no_error err
  console.log warnings
  cb()


