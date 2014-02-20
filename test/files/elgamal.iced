{KeyManager} = require '../../lib/keymanager'
{do_message,Processor} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'

#=================================================================

planck = {
  passphrase : "mmpp",
  key : """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)

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
""",
  encrypted : [ """
-----BEGIN PGP MESSAGE----- 
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

hQEOA6GRDo3EkelYEAQAtn66+B8ORT92QlHMY2tVLFbhoLdcRvkG9lM2X0op4iXk
PlgNps2UPPMEdSejVLV16evuUBS392+QqkHFLv9dZG+hheWs5opkWo7gyTZLjtSs
4YesHgjt9zqTg3ZfDjfqA2caDoUx09SvrxZyIggTQ4HsGqcq7CM1bZLWlrnBfNoE
ALCv0ou6I9sKNZazuO7yuAlL93IEE31jncooN2A5iFuM1ZknikYQh1M1PXNpocEb
+RCfDvyXMOVPrmAh6tJTswoimFYOaLCjFX/QIheIplDhsmZ1i5hvlmQBep1XC45i
cPuZ7I3F1pHz+mmfo3EDUpnHuJckMq99B0VAGMf/zAkv0qwB786ul+QxuRsAAIt5
1OnzQLadPGusI9k7gXRIh9VMDTPX06Mys16fR0+LfKTsegzKY5cQzFfnN8SS4sTt
gyA/brLHuHiFc9dSrmryNSw3k3Y7CWmpI1pQrEq9aeYd2qXtmpsWFG7K/uIXtJna
xGF/s+kzNRDrRQAD9xiCjpJaPrNP3FR5mM1m2AcXzOutycvJV8MNicOfqMaq5W1a
X0uqWT6kHA/R7W9wiqmX
=nrqo
-----END PGP MESSAGE-----
"""
  ]
}

#=================================================================

exports.decrypt_msgs = (T, cb) ->
  o = planck
  await KeyManager.import_from_armored_pgp { raw : o.key }, defer err, km
  T.no_error err
  await km.unlock_pgp { o }, defer err
  T.no_error err
  cb()

#=================================================================

