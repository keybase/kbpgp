
{KeyManager,unbox} = require '../../'

msg = """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

hQEOA6GRDo3EkelYEAQAoKCfocrq8GebAg9zBQmb+jrjPU5n8wULkzedxtgRDoQP
nmfOpVF7EbdsooQzXrzQrbTKJHkMSTNb22PQvZ6w0p/iwwiNGKA2wCKiQENKNIKq
gLUs0VX63NV1zmxxbLc+jbBArudrJkTYdRwRXEsqEpYqTsHqGvxhG6uoZo6EdVoE
AL2iLF5kK+qLUwylTEbLD9c748ltrWovBdso39IRGQuQ8hxrw7I2Ikn8fUf5o/XA
jWQLTN3a91D5F3aZUrEvFcmzhCKWZGQs+aiA4XOn6CbTOFTLmXQkBXyRL2WybCWH
LhapT79mBKsF/ahQOoAbBpLUAR+zBC6pfNWs0qOR7jBP0sBCAaBSMJES4dG9xGyh
5of/uee3o1hNXjjE4DbW6O0NVxpMYfCOh5a/C/LbQpAQuc9yBvqCz2WY4xqMeR8U
iSfEIQbh0bz5wHIuPA0HV6ra6lXZCEwqtmM2aVWHx8ooycJrECdc4Ij2rUDzuDda
vhylx+yyiaH/2v5+AsIITIvxVgIPBDvb/UiDJPrpE/+AlG/S8Ii+ovxdlNegd1no
xPJcCyxxgnvtyEppScPOmEysC+l+WhDB/m+JEL85oBgfpbOpMFEtXRoBXYTehOA8
G7nR8f6cvdJ/SjCr4PjIYQhV/MzAdsQvnh/15OOI/uFi+xrkZ/1Q4/uj2RTSvF4a
C3MCYobj
=I5z9
-----END PGP MESSAGE-----
"""

decryption_key =  """

-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQHhBFMGAboRBAC6X5nu5PxK9eaTRTGI1PUu89SYaDCNf4P82ADVwBy2gQSHZAlH
d1esdd5QI2TYvfLBYHelTLk6nfO/JsPFFTPAKiyCA84GO3MBXebs8JBd5VPl3PuY
YXk+xUVui/oE2bnS2PzUIPIilWwN1g6O4Olz+D70uuoGV8Og2krKUkzsRwCg+KcF
fiJsfgw7to/VXdD651DSZ/0D/3N5l1kiFZvttYSu6VymG76NBnPgbRKH3sYguGPj
c8E6GtJ1HrGQiGoiKN3jfYEQcOqil6/A780Yz/3yW6QK3OIJ9mIpNA8uJghWdk9E
3xhm0QrC4e3ECqQgAp5wGTfTaepsvjZxRyvu+xTQje/QMwEk3ElSOfjfq1nzjoE8
15YcBACzroFdReanDhMeRb2xjv8fjr98WqMGVjifPwJ2UEwtV8wPPGDNN63BbhYL
RyRxSrUdP3LDKnnNVocNOjOEGzrRtdKRf3S1cB7b+Tc2rphublG1yGIjDeNZ9E9g
mTrxr+mBm3WyFlBU3vEE+UJ3YLPQ37ai83CItaT22OY5FNAW3v4DAwIBuwNTyCVg
19Z/bQbO5Vv7myq59sSwfpLCcnjaII3oYjRYum32OrmIl1a2qPzOGpF1BfeyfT43
kin3XbQ1TWF4IFBsYW5jayAocGFzc3dvcmQgaXMgJ21tcHAnKSA8cGxhbmNrQGJl
cmxpbi5hYy5kZT6IaAQTEQIAKAUCUwYBugIbAwUJEswDAAYLCQgHAwIGFQgCCQoL
BBYCAwECHgECF4AACgkQkQqdjReS9VtG9ACeKf/N+cRCTEjARwbAWl9VAndRTvIA
mQE+l+Mv2PF8F3TUVVYl9aAXc3JHnQFYBFMGAboQBADSFqRZ8S7vJLXKW7a22iZR
4ezEGM4Rj+3ldbsgs+BHG3qrtILdWFeiXRfh+0XgSJyhZpRfPYeKdF42I0+JvFzF
QE/9pX5LsjeIgeB3P6gMi7IPrF47qWhixQ3F9EvBymlFFCXnJ/9tQsHytIhyXsZH
LD9Vti6bLyz8zkuXbRT8CwADBgP+LPUlmmIuuUu7kYMCLDy5ycRGv/x8WamSZlH3
6TBY44+6xIpzOGf1Aoag+e7b+5pJE5+dFfWhfvZpGn9tdLdimA7DVxl/YCeTxoXL
25YCnOhlqVFfWMnVr7Ml3hX0Hl3WXqRQT45ZR7qzfR+8xUvl6jTwYZzYElGIJxa5
hPreyJv+AwMCAbsDU8glYNfWXpn3WV1KYjnXsZwPA1zOth8DoZBvsNFgpJCxQpfI
PCeAcnTQQaF0NEEfXtNGKsbwYFdHTD7aXvAs2h05FReITwQYEQIADwUCUwYBugIb
DAUJEswDAAAKCRCRCp2NF5L1Wx7xAJ0a2tmT1WhB9+7IEHVkwm0b97EbJQCfcoDT
ZbLGiqgjXIjfEuNACFhveec=
=66In
-----END PGP PRIVATE KEY BLOCK-----
"""

exports.run = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : decryption_key }, defer err, km
  T.no_error err
  await km.unlock_pgp {passphrase : 'mmpp' }, defer err
  T.no_error err
  await unbox { armored : msg , keyfetch : km, strict : false }, defer err, literals, warnings
  T.no_error err
  wv = warnings.warnings()
  T.equal wv, [ 'Problem fetching key 11e8aed7fa9fbb74: Error: No keys match the given fingerprint'], "the right warnings"
  T.equal literals[0].toString(), "hi, this is a test message\n", "the right message decrypted"
  cb()
