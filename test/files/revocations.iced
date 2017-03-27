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

  class KeyRing extends PgpKeyRing
    fetch: (key_ids, ops, cb) ->
      await KeyManager.import_from_armored_pgp { raw: key }, defer err, km
      @add_key_manager km
      super key_ids, ops, cb

  await do_message { keyfetch : new KeyRing(), armored : message }, defer err, outmsg
  T.assert err, "All good - failed to verify"
  cb()
