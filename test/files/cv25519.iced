{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
km = null
top = require '../../lib/main'

exports.import_private_cv25519_key_from_gpg = (T, cb) ->
  priv_key = """-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEV/bL8xYJKwYBBAHaRw8BAQdA/tN2DTMq9IDsDjE+d0jdrQv4nUh15IwhEuK6
98RzHTAAAQC6gzVTi8V5Eis0pBg8g0iW0hp++dPczDXGg+Kc1jkzEw+ItB1NaWNo
YWwgWiAoMjU1MTkpIDxtQHphcHUubmV0Poh5BBMWCAAhBQJX9svzAhsDBQsJCAcC
BhUICQoLAgQWAgMBAh4BAheAAAoJEOctHO20d21/oE8A/jeDMoqnVrart8PlBBOh
U7POysui1CFQb4bYokaURPNzAQCE7gJ0oD2pOlU6zgia1+6JPfAnUL8rQ4PFsZ7b
5gT2BpxdBFf2y/MSCisGAQQBl1UBBQEBB0DR3in/BpS2e2jyZL1lX+DrUzJwXeQs
6CTF+o83Jt32UgMBCAcAAP9tMK39aEcGzSUmICdAqybiurbh1anP453af1dwgiRb
8BF8iGEEGBYIAAkFAlf2y/MCGwwACgkQ5y0c7bR3bX9JPgEA7WiFuFuTI4L0e8mV
3UeahfoOyLOY71uHDNdfB66DCa0BANK4aMk+j7bpJoWFNpkWq9JnhpfXV9L2dh3R
kKuKwZkI
=RN+z
-----END PGP PRIVATE KEY BLOCK-----
  """

  await KeyManager.import_from_armored_pgp { armored: priv_key }, defer err, tmp, warnings
  T.no_error err
  T.assert tmp?, "a key manager returned"
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  km = tmp
  cb()

exports.decrypt_cv25519_encrypted_msg_from_gpg = (T, cb) ->
  msg = """-----BEGIN PGP MESSAGE-----

hF4DR1BH23/8iIwSAQdAAFSLQplsmPX/IeOmXWLVRkHt680ioHhESGVPBcM+aykw
22/IiXZdq5ZH3muKbFFHfGQNEUSMQgkum5nggyPFhe/iP2jqzso6yI7ThOU/AlEF
0kcBPJvpEj0IDl271FMwUcyVrZSGA7G+tgIVvdwXcmHCi1EugjWFCYCIZRZ0WWaY
Lf8VY48iRD084UYhvy6Y8/wKWdHe7mnC2Q==
=U1oU
-----END PGP MESSAGE-----
"""

  await do_message { armored: msg, keyfetch: km }, defer err, msg
  T.no_error err
  T.equal msg[0].toString(), "hello kbpgp\n", "got the right plaintext"
  cb()

exports.roundtrip_cv25519 = (T, cb) ->
  plaintext = """
  This is the eternal kingdom of Zeal,
  where dreams can come true.

  But at what price?
  """

  await burn { msg: plaintext, encrypt_for: km }, defer err, aout, raw
  T.no_error err
  await do_message { armored: aout, keyfetch: km }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "decrypted text matches plaintext"
  cb()

exports.roundtrip_cv25519_with_sign = (T, cb) ->
  plaintext = "A.D. 1999! At 1:24! Data confirmed!"

  await burn { msg: plaintext, encrypt_for: km, sign_with: km }, defer err, aout, raw
  T.no_error err
  await do_message { armored: aout, keyfetch: km }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "decrypted text matches plaintext"
  T.assert (msg[0].get_data_signer()?), "was signed!"
  sign_fp = msg[0].get_data_signer().sig.key_manager.get_pgp_fingerprint()
  start_fp = km.get_pgp_fingerprint()
  T.equal sign_fp.toString('hex'), start_fp.toString('hex'), "signed by the right person"
  cb()

exports.decrypt_verify_gpg2_issued_payload = (T, cb) ->
  cipher = """-----BEGIN PGP MESSAGE-----

hF4DR1BH23/8iIwSAQdAUTwRita4uQy4jEwGbx4WBDs0FbX8CnG3SwJm3EHNhygw
pJEr3nI4BP85u/6zZshxo/NbIFrzOdpcAGjbja02Ep/MP4xk22WEpdJQ+z5vu8yr
0qwBzkfy6OqiZVXBJz2Np2lvbJNJr+uPAJ5ZQ/RAsQKJEaP8qHBVORv9mkv8QsaX
l8WgAyTMyFMF7V/C2Ju3mgmgeQXur7HJq3kxeoh02pjxvWO85zimV7VDYrMeduDV
WsvF/TEAEghhpkEZHEAg+QuyZKzrqwU+SqnVnffJyZVCeXH28/iTyoeIfJIFMpIi
7mbyEN/uagIbrLg0gB3tmK3FEjFKEkDocJV7HrSd
=SFDG
-----END PGP MESSAGE-----

"""

  await do_message { armored: cipher, keyfetch: km }, defer err, msg
  T.no_error err
  T.equal msg[0].toString(), "\nasd\n", "got the right plaintext"
  T.assert (msg[0].get_data_signer()?), "was signed!"
  sign_fp = msg[0].get_data_signer().sig.key_manager.get_pgp_fingerprint()
  start_fp = km.get_pgp_fingerprint()
  T.equal sign_fp.toString('hex'), start_fp.toString('hex'), "signed by the right person"
  cb()

