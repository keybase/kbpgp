{armor} = require '../../'

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

sig = """
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

owGbwMvMwCEWkaL0frulny3jaYskhtDjxT89UnNy8hVSE4tyKhUSU/ILSlKLivUU
PFKLUhUyixWK83NTFVxTXIIdFYpLCwryi0r0uDriWBjEOBjYWJlA+hm4OAVghpZl
MTL8YPwp/vm3C6/Rd+vV/I/ffbT/WJeR/89hRrgiO4fLzbgahr9yvpYXOHv0ZO5v
vbxHnotdUPRecEXJ5t6j/AZcyXGTC5gB
=wkK1
-----END PGP MESSAGE-----
"""

msg = "Hello early adopters. Here is some EdDSA support."

# console.log (armor.decode key)[1].body[18...].length