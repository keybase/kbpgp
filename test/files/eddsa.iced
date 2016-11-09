{unbox,KeyManager,armor,ecc} = require '../../'
{burn} = require '../../lib/openpgp/burner'

## Keys and sigs in this file generated with GPG v2.1.6

key = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mDMEVcdzEhYJKwYBBAHaRw8BAQdABLH577R+X2tGKoTX7GVYInAoCPaSpsaJqA52
nopSLsa0K0Vhcmx5IEFkb3B0ZXIgKFBXIGlzIGFiY2QpIDxlYXJseUBhZG9wdC5l
cj6IeQQTFggAIQUCVcdzEgIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRBY
ZCLvtzlOPSS/AQDVhDyt1Si33VqLEmtlKnLs/2Kvi9FeM7yKU3Faj5ki4AEAyaMO
3LKLyzMhYn7GavsS2wlP6hpuw8Vavjk2kWE7iwA=
=IE4q
-----END PGP PUBLIC KEY BLOCK-----
"""

sigs = [ """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

owGbwMvMwCEWkaL0frulny3jaYskhtDjxT89UnNy8hVSE4tyKhUSU/ILSlKLivUU
PFKLUhUyixWK83NTFVxTXIIdFYpLCwryi0r0uDriWBjEOBjYWJlA+hm4OAVghpZl
MTL8YPwp/vm3C6/Rd+vV/I/ffbT/WJeR/89hRrgiO4fLzbgahr9yvpYXOHv0ZO5v
vbxHnotdUPRecEXJ5t6j/AZcyXGTC5gB
=wkK1
-----END PGP MESSAGE-----
""",
  """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

owGbwMvMwCEWkaL0frulny3jaZckhtDj0+55pObk5CukJhblVCokpuQXlKQWFesp
eKQWpSpkFisU5+emKrimuAQ7KhSXFhTkF5XoKYRkpCoUpybn56XocXXEsTCIcTCw
sTKBzGLg4hSAWZBvzsjQ2RN1KfRR5AHXG+wHZx8w1Jd8r1f6/5lqY+GxmNkse0uK
GRn+rGaeX+fDyVLmzMVosu3hAaZjC5/FiEskfxSuZNlwpI8LAA==
=Ks12
-----END PGP MESSAGE-----
""",
  """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

owGbwMvMwCEWkaL0frulny3jaeckhtDjM5g9UnNy8hVSE4tyKhUSU/ILSlKLivUU
PFKLUhUyixWK83NTFVxTXIIdFYpLCwryi0r0FEIyUhVKMjKLUvS4OuJYGMQ4GNhY
mUBGMXBxCsDMP7GA4X/4JlF9p1uHWr2yn/o+l1uRdcFn6xp7zq2/PzDZyqr0h+xk
+J9mYZEyTzxYwov3+41tk1POxp2d4xzP7qhw+vSpjus5sswA
=Eywk
-----END PGP MESSAGE-----
"""
]

msgs = [
  "Hello early adopters. Here is some EdDSA support.\n"
  "Hello early adopters. Here is some EdDSA support. The second.\n" 
  "Hello early adopters. Here is some EdDSA support. The third.\n"
]

#------------------------

km = null

#------------------------

exports.import_key_1 = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : key }, defer err, tmp, warnings
  T.no_error err, "should have parsed"
  km = tmp
  cb()

#------------------------

exports.verify_sigs = (T,cb) ->
  for sig,i in sigs
    await unbox { armored : sig, keyfetch : km  }, defer err, literals, warnings
    T.no_error err, "no errors pls #{i}"
    T.equal literals[0].toString(), msgs[i], "message #{i} was correct"
    T.assert literals[0].get_data_signer()?, "message #{i} was signed"
  cb()

#------------------------

exports.generate_key_and_sign = (T, cb) ->
  params = { userid: "Mr Robot", ecc: true, primary: { algo: ecc.EDDSA }, subkeys: [] }
  await KeyManager.generate params, defer err, kb, warnings
  T.no_error err, "no errors"
  msg = "Chancellor on brink of second bailout for banks"
  params = { msg: msg, sign_with: kb }
  await burn params, defer err, payload, warnings
  T.no_error err, "no errors"
  await unbox { armored: payload, keyfetch: kb }, defer err, literals, warnings
  T.no_error err, "no errors"
  T.equal literals[0].toString(), msg, "message was correct"
  T.assert literals[0].get_data_signer()?, "message was signed"
  cb()

#------------------------

exports.sign_and_exchange = (T, cb) ->
  params = { userid: "Ms Alice", ecc: true, primary: { algo: ecc.EDDSA }, subkeys: [] }
  await KeyManager.generate params, defer err, alice, warnings
  T.no_error err, "no errors"
  msg = "LOVE-LETTER-FOR-YOU.txt.vbs"
  params = { msg: msg, sign_with: alice }
  await burn params, defer err, signed_mail, warnings
  T.no_error err, "no errors"

  await unbox { armored: signed_mail, keyfetch: alice }, defer err, literals, warnings

  T.no_error err, "no errors"

  # Export public key.
  await alice.sign {}, defer err
  await alice.export_public {}, defer err, alice_pub
  T.no_error err, "no errors"

  # Import to separate KeyManager and try to unbox the message.
  await KeyManager.import_from_armored_pgp { armored: alice_pub }, defer err, bobs_km
  await unbox { armored: signed_mail, keyfetch: bobs_km }, defer err, literals, warnings
  T.no_error err, "no errors"
  T.equal literals[0].toString(), msg, "message was correct"
  T.assert literals[0].get_data_signer()?, "message was signed"
  cb()
