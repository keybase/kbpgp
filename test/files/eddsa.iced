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
    T.no_error err, "no errors for #{i}"
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

#------------------------

# Key block with an EdDSA primary key with one userid with invalid
# signature (so the primary key is not "self signed").
invalid_signed_pub = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEWMehfhYJKwYBBAHaRw8BAQdAkPjZ3KqkgQBYJ+QtVMyKeUtcNSnGRVCl7fqh
zu6+/iPNB01yIFRlc3TCdgQTFgoAHgUCWMehfgIbLwMLCQcDFQoIAh4BAheAAxYC
AQIZAQAKCRAyRxe+NnRYwkfYAQDPDO2CuFm8GWmVRBnMlXRBXEJxiPw5kyxj1OyX
W1V5BwEAljWDLDmGj01/Kof6U8McEE4JNI0rLQ31ZdVPQG/S9AU=
=ttjQ
-----END PGP PUBLIC KEY BLOCK-----
"""

exports.invalid_signed_key = (T, cb) ->
  await KeyManager.import_from_armored_pgp { armored: invalid_signed_pub }, defer err
  T.assert err?, "importing should fail"
  cb()

#------------------------

# Key is valid, but the message has invalid signature

key2 = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEWMekoBYJKwYBBAHaRw8BAQdAGXBpshF3yaBi3MPsSOR1NhRG96wLsvAEAvQT
DUiMUBfNB01yIFRlc3TCdgQTFgoAHgUCWMekoAIbLwMLCQcDFQoIAh4BAheAAxYC
AQIZAQAKCRBndBUOnFoQIgINAQDlFMzAKR1foEc4jDP+7ysHQEah6RNDnnIqNHAZ
b/I/mwEAd/3i3sO5oOCTDv5TyKwDnUNtOaCNJliZPuBxuZkeAQQ=
=AmZg
-----END PGP PUBLIC KEY BLOCK-----
"""

msg_w_invalid_sig = """
-----BEGIN PGP MESSAGE-----

yJQCeJw7wsvMwCWWXiLKNydKQInxtGwpQ8TxJQt9U4uLE9NTFVzyU4sV/PJLFHwT
S0pSiw7FsTCIcTGwsTKBFDFwcQrAdAqrMzJwHPzdcJ337sunM9/7fgzmfvfLevUB
r7fWrAw8vPsrz9oyMDLM7BTUkT4y8dzUyXN3za3fH3oz9/Ssy3JiJrc58zin7bsh
CwBfXTWS
=JVLN
-----END PGP MESSAGE-----
"""

exports.invalid_signature_msg = (T, cb) ->
  await KeyManager.import_from_armored_pgp { armored: key2 }, defer err, keym
  T.no_error err
  await unbox { armored: msg_w_invalid_sig, keyfetch: keym }, defer err, literals, warnings
  T.assert err?, "message should fail to verify"
  cb()

#------------------------

# Minimal repro for: https://github.com/keybase/keybase-issues/issues/2787
# Public key had multiple identities, one of which had a signature
# that had S component of 31 bytes (instead of 32 for valid EDDSA). We
# should be able to parse such key but fail the verification (so one
# of the userids will be usigned)

key_second_userid_invalid = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v2.0.65
Comment: Second userid has invalid signature (S shorter by 1 byte).

xjMEWMe+KxYJKwYBBAHaRw8BAQdACovM/A9hqvpSk6ye0Dic/qhIXnACG7TvZ7Fm
KQoLcizNGU1yIFRlc3QgPHRlc3RAa2V5YmFzZS5pbz7CdgQTFgoAHgUCWMe+KwIb
LwMLCQcDFQoIAh4BAheAAxYCAQIZAQAKCRAk7Ki+jWkPk38dAQAA1YGs4U8erWBd
/zuMACKX9dJbEaMpYknQpqvxYrkPvwEANOskGrr3G/kWUkIrjKnbjvwbDPifwa5V
A73D7La5QQ7NG01yIFRlc3QgMiA8dGVzdEBrZXliYXNlLmlvPsJyBBMWCgAbBQJY
x74rAhsvAwsJBwMVCggCHgECF4ADFgIBAAoJECTsqL6NaQ+T0TEBAMGoORS2uUF7
kGOZKibkwoGC8irPGmBzN6tAf+ravK+HAPg7A3NA+Yqr+aTzl2xSXqIAOb2fJjIA
AC0Xg++AATao
=uJ/2
-----END PGP PUBLIC KEY BLOCK-----
"""

exports.invalid_userid_sig = (T, cb) ->
  await KeyManager.import_from_armored_pgp { armored: key_second_userid_invalid }, defer err, keym
  T.no_error err # imported fine
  T.assert keym.userids.length is 1 # but only one userid (of two)
  c = keym.userids[0].components
  T.assert c.username is 'Mr Test' and !c.comment? and c.email is 'test@keybase.io'
  cb()
