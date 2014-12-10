{KeyManager} = require '../../'
{do_message,Processor} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'

#=================================================================

dlg =  {
  key : """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

mQGiBFMFCfkRBACWAeNfoYui4Kmg/Z6x0wTiUyAc2qO4k0mn2nDRxg2ieKxoQYAu
mv8VIdlUdokAblfoaBRjuN7tfB4D+wvGskgEPpIVBDTLylnzLSr/gZENKif0WQNm
fIMsgUYjjx+HbEcdyF1aQZ8u6uvwjLkHYvuRc6hcf4jy1TTGMYxgbzJJewCg5wrQ
Uc4gfhwzqrWWCfkZDv0wuScD/0pVgq8gk0BtTfncKfYdNzGe/sEEKC2YWUKDDXM6
U9g4o+V45KxX6CRTxPx6ZtnAyVY0jA+C2Ad0YAiTJloQSjTR5mOcff7Q4Y5TNdgi
wkIe/nJsfKMzbAcAp1rTOf8GRmyjGmH4y3agKD2dWAqZ5DVufN6zAe+Uo+6pGJmU
yyYsA/wMQYSodf8rVZOtgtH7Rt26VxHj3Mjl/BC+lDjVB+hHexYZf/uRxbcmUnVd
ZY+H2Z0gvCjgC/KFyJmWpsuomUs06ODzq2hq1yJRqeHqDvPp+8yJVsvOsdo6oKOz
fS295sIpo/2yYjloaIZu8d4Uz5wY8GaKSX8UZ4FL2mjhAqEhpbQfRGF2aWQgTGxv
eWQgR2VvcmdlIDxkbGdAZ292LnVrPohnBBMRCgAnBQJTBQn5AhsDBQkSzAMABQsJ
CAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEHGE0rkf9XmXw8MAmQGB2V8G75S5JTke
LWYec+iIb4cDAJ9p2To50haAhlBC024W91cmddudZg==
=VRBx
-----END PGP PUBLIC KEY BLOCK-----

""",
  sigs : [ """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

owGbwMvMwCRY2HJpp/zXyumMp32TGIJZeab75ZcoJCWm5FTqKCTn5xVnpqQWZeal
K3gqlCcWKxSnJpakpigkpZaUp6bmKXilFpcWKzhnFGUWlygk5qUo+CUW5Oek5ufp
cXW4sTAIMjGwsTKBDGXg4hSA2RRxmGGuGAvn2sXdU95NC3x7Mfts0aLMJp7XDAv2
q85awd3aY9dgbP7Q0Pnnxdvqf/wA
=o8cb
-----END PGP MESSAGE-----"""
  ]
}

#=================================================================

exports.verify_sigs = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : dlg.key }, defer err, km
  T.no_error err
  fp = km.get_pgp_fingerprint().toString('hex').toUpperCase()
  T.assert fp, "a fingerprint came back"
  fp2 = "91D6582E37E81A9A7F19D2F57184D2B91FF57997"
  T.equal fp, fp2, "the right fingerprint"
  for sig in dlg.sigs
    await do_message { armored : sig, keyfetch : km }, defer err, literals
    T.no_error err
    T.equal literals.length, 1, "only got 1 literal packet back"
    lit = literals[0]
    signer = lit.get_data_signer()
    T.assert signer?, "we were signed"
    fp3 = signer.get_key_manager().get_pgp_fingerprint().toString('hex').toUpperCase()
    T.equal fp, fp3, "the literal data packet was signed with the right key"
  cb()

#=================================================================

gbc = {
  key : """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.14 (GNU/Linux)

lQHhBFMFX/YRBACKwOOj7dkyHb8J3qDOvS0ZEcgiZnFCaLCh07GWV/S/HEelVaDF
BIVdn2Ho/j80HWkRMJAFqNBoEfqqz1n6MFxZNgUlWOOSdUIkOq2qcZhqQqcvwqJU
FxKKO7gKI037HBYlgmgD2/LGAWGZQDHDciDqcy+SEwvFB+y/x9bSSCornwCgnVzp
C77KgeXIS26JtbMeNd7x+xkD/3NjzK0jF3v7fASE2Eik+VlGiXkk8IuV32LYAtkd
Qyjw+Xqx6T3gtOEPOJWd0MlOdb75J/EMJYN+10yMCIFgMTUexL4uVRKMRBy3JBwW
kHApO+LG/2g5ZHupaqBixfcpya5N1T+sNNlPQ1pvCTANakp1ELR2BAb6g5PGuQab
scboA/9LsjYMdTqXQVCj9ck0+kSFxeBygobDqQIwd4BW2fMRzRg7kFZdICtzYSSi
2z9iHmzC+OiokPKHnVSYRKSZ5cHe/ke2SunptKzpFhWxKO5FYRODX3txvEMUUst+
FE1f/+dnLQyxY5BB1fRcpUlUtRZ453lObMm0aY652bgyW/6CSP4DAwJVX0fqCIms
8WC03phNbtqDYUIajoX+e+p8wBBUNRZo4JSV8s7OTI+MMTR0MO38+9B+cM9KKmbG
A0Clx7Q3R2VvcmdlcyBCZW5qYW1pbiBDbGVtZW5jZWF1IChwdyBpcyAnYWJjZCcp
IDxnYmNAZ292LmZyPohoBBMRAgAoBQJTBV/2AhsDBQkSzAMABgsJCAcDAgYVCAIJ
CgsEFgIDAQIeAQIXgAAKCRA350+UAcLjmJWYAKCYHsrgY+k3bQ7ov2XHf9SjX7qU
twCfebPu3y0/Ll7OdCw5fcXuzbCUbjY=
=s2F5
-----END PGP PRIVATE KEY BLOCK-----
""",
  msg : """
We have just won the most terrible war in history, yet here is
a Frenchman who misses his target 6 out of 7 times at point-blank
range. Of course this fellow must be punished for the careless
use of a dangerous weapon and for poor marksmanship. I suggest
that he be locked up for eight years, with intensive training
in a shooting gallery."""

}

exports.dsa_round_trip = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : gbc.key }, defer err, km
  T.no_error err
  T.equal km.get_primary_keypair().nbits(), 1024, "the right number of bits"
  await km.unlock_pgp { passphrase : 'abcd' }, defer err
  T.no_error err
  key = km.find_signing_pgp_key()
  await burn { msg : gbc.msg, signing_key : key }, defer err, asc
  T.no_error err
  await do_message { armored : asc, keyfetch : km }, defer esc
  T.no_error err
  cb()

#=================================================================
