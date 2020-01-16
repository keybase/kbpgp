testing_unixtime = Math.floor(new Date(2014, 2, 20)/1000)

{KeyManager} = require '../../'
{do_message} = require '../../lib/openpgp/processor'

#==================================================================

sigs = [
  {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

owEBRAK7/ZANAwACAS/gHEVDSNo5AcsbYgBTBq2LR28gcmV0cm8gbGlrZSBXb3hp
ZHUKiQIVAwUAUwatiy/gHEVDSNo5AQIjZA/+M9tnFjf0EOVOwUHYS6AYfk6rpgoP
SJcGNxpflU6nMA92AiMexlp7iyBPe7ZklkDclMNAaxelR6e9jLIEckm9qq6qw0vP
i5XhbwJnqVh0cYn+AG/PKrlxZk6ULpmFw2MRfcnftW6f3H5W1b59SvBGaUtZ1dx7
WzbGYvyPeyWHCEPoQgcv+mi5GRx4V76PLE5GdLdQdB0giCF9OqlVTcT0UFqfhJ3/
sc5u/Olyokk7RAFjC9qoEMsGTJcF1A5Rk5PVfaS9O/UbFkxsU/uqRx6Lb3hyjNf5
7c2hl7qGVOuZk6RSC3/jEZbbHhiSAd01LOS5TgQRaToZa4+NX8oXwWBc8Oa4iva4
gHbgusStDjsUCXl8IWS8xogryQbxxnhC9cNdmdnBWZwQJufZXlK7BgQyRiBSTlap
yBKxX1oP1iMIlLuVT8KsbSAHBjREPv9weHGjzJEjIhLT+RcW56vWaL5qTwOWOOXi
FDtyU0zLcBIxDIGxYb1eAMBWavpWp6mwqNOkFrSggOgsH/MygLQ5lshgCrYBu36q
e4ED3iMdzAI6fV5jaDvYRQRLjBSdzl+JCAbIf/pLLP8H8Pl3/CVgS96M6ztq7Gsc
m2FCDrioktpkjzM4VBw6UVipPmvAYHQ5BxQIFZ6gFdE9JkIF45o50QnmNd3BTizT
oAn9gpIRZacCPbs=
=63G5
-----END PGP MESSAGE-----
""",
    key : """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

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
7lu5/Zw+Z6JiUl0p
=TUk8
-----END PGP PUBLIC KEY BLOCK-----
"""
  },
  {
    sig : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

owGbwMvMwCRo/tx/CuOhxzMYT0snMQSzrVByz1coSi0pylfIycxOVQjPr8hMKeXq
sGdmBcvClAsyyagyzFNVDN3Ut0R7yV7Wkj0bkl4z7VzcdJhhvqea9W6B3F2ltuFG
+yZ9s1R9rHazFgA=
=HIJN
-----END PGP MESSAGE-----
""",

    key : """
  -----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

mQGiBFMFX/YRBACKwOOj7dkyHb8J3qDOvS0ZEcgiZnFCaLCh07GWV/S/HEelVaDF
BIVdn2Ho/j80HWkRMJAFqNBoEfqqz1n6MFxZNgUlWOOSdUIkOq2qcZhqQqcvwqJU
FxKKO7gKI037HBYlgmgD2/LGAWGZQDHDciDqcy+SEwvFB+y/x9bSSCornwCgnVzp
C77KgeXIS26JtbMeNd7x+xkD/3NjzK0jF3v7fASE2Eik+VlGiXkk8IuV32LYAtkd
Qyjw+Xqx6T3gtOEPOJWd0MlOdb75J/EMJYN+10yMCIFgMTUexL4uVRKMRBy3JBwW
kHApO+LG/2g5ZHupaqBixfcpya5N1T+sNNlPQ1pvCTANakp1ELR2BAb6g5PGuQab
scboA/9LsjYMdTqXQVCj9ck0+kSFxeBygobDqQIwd4BW2fMRzRg7kFZdICtzYSSi
2z9iHmzC+OiokPKHnVSYRKSZ5cHe/ke2SunptKzpFhWxKO5FYRODX3txvEMUUst+
FE1f/+dnLQyxY5BB1fRcpUlUtRZ453lObMm0aY652bgyW/6CSLQ3R2VvcmdlcyBC
ZW5qYW1pbiBDbGVtZW5jZWF1IChwdyBpcyAnYWJjZCcpIDxnYmNAZ292LmZyPoho
BBMRAgAoBQJTBV/2AhsDBQkSzAMABgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAK
CRA350+UAcLjmJWYAKCYHsrgY+k3bQ7ov2XHf9SjX7qUtwCfebPu3y0/Ll7OdCw5
fcXuzbCUbjY=
=FQCZ
-----END PGP PUBLIC KEY BLOCK-----
"""
  }
]

#==================================================================

verify = ({sig,key}, T,cb) ->
  opts = now : testing_unixtime
  await KeyManager.import_from_armored_pgp { raw : key, opts }, defer err, km
  T.no_error err
  await do_message { armored : sig , keyfetch : km, now : testing_unixtime }, defer err
  T.no_error err
  cb()

#--------------------------------

exports.verify = (T,cb) ->
  for sig in sigs
    await verify sig, T, defer()
  cb()

#==================================================================
