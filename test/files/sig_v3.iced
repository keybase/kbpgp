{KeyManager} = require '../../lib/keymanager'
{do_message,Processor} = require '../../lib/openpgp/processor'

#==================================================================

sigs = [{ 
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

}]

#==================================================================

verify = ({sig,key}, T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, km
  T.no_error err
  await do_message { armored : sig , keyfetch : km }, defer err
  T.no_error err
  cb()

#--------------------------------

exports.verify = (T,cb) ->
  for sig in sigs
    await verify sig, T, defer()
  cb()

#==================================================================

