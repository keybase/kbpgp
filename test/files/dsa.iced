{KeyManager} = require '../../lib/keymanager'

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
  await KeyManager.import_from_armored_pgp { raw : dlg.key }, defer err
  T.no_error err
  cb()

#=================================================================
