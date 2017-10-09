{KeyManager} = require '../../'
{do_message} = require '../../lib/openpgp/processor'
{PgpKeyRing} = require '../../lib/keyring'

exports.verify_revoked_with_keyfetcher = (T, cb) ->
  # There was a bug/API misuse where PgpKeyRing subclass would fetch a
  # key from remote source and then call `super` to give control back
  # to the base class. Revoked keys were not properly filtered out and
  # were still returned from fetcher coded in this fashion, so they
  # would have been used for verification and other operations.

  key = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWNU+YBYJKwYBBAHaRw8BAQdANDGlomfqnHvB2suF9Nsk27qprv4jyqUnGUxT
ezS17DyIYQQgFggACQUCWNU+6AIdAwAKCRByQpSZUUdJMCiQAQCA90BeuZfzJuEr
SzTT76qks97wmTYTCI2Tklnkgfw9UAD/WJMsBW93I8YERc6TaAM7Ikw/XxF/Llhb
WXmitXrgbQ+0ElJldm9rZWQgS2V5IFRlc3Rlcoh5BBMWCAAhBQJY1T5gAhsDBQsJ
CAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEHJClJlRR0kw3sEBAIc6PaPdgHIsi5Pz
xZkDfwVa76Mvb8yug8HIW9A9swmYAP0ZSASv7N+f6wZUSJAun9E7pnfaA0y+bVs4
Wk0U7dsXDrg4BFjVPmASCisGAQQBl1UBBQEBB0CLNBYcjHxNQGfO8fcyp+QtsC8P
d2dLxZR10SQnIaQWPAMBCAeIYQQYFggACQUCWNU+YAIbDAAKCRByQpSZUUdJMCot
AQDaW0YiRIN64fCmnSJFNZTqM1V1VE1tLktUxwT5uilB9QD+JcppXFBLPB0oSlMu
2LPpIrS71kVwXb+yF3Rr8c87uAE=
=aPLq
-----END PGP PUBLIC KEY BLOCK-----

"""

  message = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

This message was signed by a key that is revoked. It should not pass verification.
-----BEGIN PGP SIGNATURE-----

iF4EARYIAAYFAljVPqgACgkQckKUmVFHSTB7SQEAn2D5cUbMp7/HTY+8v54uz7gL
V1lAVqcNiyy7Srus5/UBALbH5jUIR2kZamWO0znZ7+ltz42cmZ+OESnfHxa4KUUB
=+5R5
-----END PGP SIGNATURE-----
"""

  now = Math.floor(new Date(2017, 4, 1)/1000)

  class KeyRing extends PgpKeyRing
    fetch: (key_ids, ops, cb) ->
      opts = { now }
      await KeyManager.import_from_armored_pgp { raw: key, opts }, defer err, km
      @add_key_manager km
      super key_ids, ops, cb

  await do_message { keyfetch : new KeyRing(), armored : message, now }, defer err, outmsg
  T.assert err, "Failed to verify"
  T.equal err.name, "RevokedKeyError", "Proper error"
  cb()

exports.verify_keyfetcher = (T, cb) ->
  # Do similar test as above, but with key that is not expired.
  keys = []
  keys.push """-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEWNkB0RYJKwYBBAHaRw8BAQdA4hcG1GlHLKQu1e3wGlt1nYOnanUIDZ+khCKC
jCsK5NYAAP4nvoBNpeP4MY36+z9YDh+ErdxWaMzCmGCHdMjydARScRHotAVBbGlj
ZYh5BBMWCAAhBQJY2QHRAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJELy7
f0GiDfzHy1gA/jdhdJf909xthPBDQsrwqISP4dLTWuC3BVSS6EKA9NPwAP9rJr8r
exCp67hEbgh3DW6PvRTE98uQ2xq9DwsE20/kBJxdBFjZAdESCisGAQQBl1UBBQEB
B0CLllnTNJJe8P6LegVgpvQcf4HNP5saxm5KKWIYCaowWQMBCAcAAP9hVRqTSXVt
JZMEQbb+cifABP4nV0u5rqDhl6s+iwiBeA9WiGEEGBYIAAkFAljZAdECGwwACgkQ
vLt/QaIN/MdpZwEA/nnrXhSvAQ/5vgRxE1MEgCtjqlUf4wBjOu/k+LhFcWUBAO2i
25EtZWVtDKcJfQILvethtIglGMk8Dc3dcH9FSywC
=LH1D
-----END PGP PRIVATE KEY BLOCK-----
"""

  keys.push """-----BEGIN PGP PRIVATE KEY BLOCK-----

lNkEWNkCiRMFK4EEACMEIwQBsUDs05PSWR3j3/yfnG/MYq8tJwXUymCP6GPhuLn1
g7FdKvxGvx9S9QEzMo3M6x2x515ywYrKhS6+GdaXhD/7vpcAUQdjLyzYWrHtE50q
zoxUjQ3Z5rDeNF9+YAOwvntwWi5xsIVAsKbW/yWqq+YnazZmcYr3Oj5/61z69uvL
sw7JX64AAgjz1cim3YvBwqnmNBnQeS5aLyO7QVBjjsOLrVWA1iGmXWokS7iVJYRP
1zQJwHe2zft7N4L+bPiQPjjJsbqEsijFsiK9tAVCb2JieYi9BBMTCgAhBQJY2QKJ
AhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEONJWG038qWKGYQCCQEbZzUx
0qkMFdJXUvNIZ/nBU64SY+I1akBDKGdZ0uNSzi1pkwW8lUYngVLM806Ya1gxeYwz
SxKAU1lV2N9T/OwMkgIJAWFarehjKORU145RHNlF6CDmtppxdYWu/7eN0VEjpZMm
xa3+AabFEd7UxVWtsoJO6IZBbH+bxN7nH0VqdZPCW9xn
=88gx
-----END PGP PRIVATE KEY BLOCK-----
"""

  message = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hi Alice!
-----BEGIN PGP SIGNATURE-----

iF4EARYIAAYFAljZAscACgkQvLt/QaIN/MeyogEApVNXk3huA7BnMBka1FcMm3qy
RDwSBZOCIiqrUdoX8FEBAMSoFWK+JFjurbSBFhJsU9IVoJRXok8Nx0ykF4tXeKEG
=yUJK
-----END PGP SIGNATURE-----
"""

  class KeyRing extends PgpKeyRing
    fetch: (key_ids, ops, cb) ->
      for key in keys
        await KeyManager.import_from_armored_pgp { raw: key }, defer err, km
        @add_key_manager km
      super key_ids, ops, cb

  await do_message { keyfetch : new KeyRing(), armored : message }, defer err, outmsg
  T.no_error err, "Message verified"
  T.assert outmsg?.toString() is "Hi Alice!"
  cb()


