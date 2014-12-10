{KeyManager} = require '../../'
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
  encrypted : [
    {
      ciphertext : """
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
""",
      plaintext :  "My unavailing attempts to somehow reintegrate the action quantum into classical theory extended over several years and caused me much trouble.\n"
    }
  ],
  signcrypted : [
    {
      ciphertext : """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)

hQEOA6GRDo3EkelYEAP9Eu7momivfWhIXFtkbM9ZmGBiLNP9Doq+jy7IPFMvKanK
7dv6Dv4RFcT+3WiphiWdgUXQwawyLL/2r1DYWw5CJ15RMUfnSVVQJw2k+2fxOyug
cJAXuIYVZ6AYU27NESlBje4cYaXk2kvdbYZ5wHRNGixlnyOmPCxsYDiHSKLHcHME
ALlyvqxpi01ZYW6ZKE58pvs45fj95l7KHZmIqCgzEEKvKk/w2Si0699bs05ldPAw
uO3d2MQP6VsxhzgiAE5B6B/fXpnK5aUuoRmAhJvnVoM2ZAguZTgLLhR2Ma+7cvMd
Da9o3Hzz/T2UBf0qRQ3X9O66WNKe4Xipp++p/V/WJ6u10sB4AWm/Bw16rweXQGpN
/TAVQBfdbACLPuOme3Bv9IZs5q5Ou5UB90kPcyIEyvtE0gujtgU4S1Pdby5Gh2qI
g3qImF1c6q67r16MVLtjt59L81/hpFARGpxI02nKecLXPIXhItsQXf8e7PjVRNLt
mH1vSFZuUunqJI2+6LmjKLSFfPZt0osEyxKQ3tY/F/jBsR3f1pU5U5Ms9FojqtB4
e0X6VqyJrw8xauQJWNfQ1CC1T4Vl/DhX7ObCRwdpaCfh2i+1RyROxMfmvMTSCyQb
Lv972c/jTKdnsTfxWp7zroX1kzzsUUhjV91GnWAtZzKcOyDXlqUZqObVObMD8wpA
CcZLYRrvnqrtjVDtBpbliNOMc+BE2zCot1ZGUFyqkw6pskUxxRXf4xfa0eys2HjG
2DhxByChz0SGgnRO
=haPD
-----END PGP MESSAGE-----
""",
      plaintext :  "A scientific truth does not triumph by convincing its opponents and making them see the light, but rather because its opponents eventually die and a new generation grows up that is familiar with it.\n"
    }
  ],
  quotes : [
    "Something something foo foo bar bar should be better no time."
  ]
}

km = null

#=================================================================

exports.decrypt_msgs = (T, cb) ->
  o = planck
  await KeyManager.import_from_armored_pgp { raw : o.key }, defer err, tmp
  km = tmp
  T.waypoint "key import"
  T.no_error err
  await km.unlock_pgp o, defer err
  T.no_error err
  T.waypoint "key unlock"
  key = km.find_crypt_pgp_key()
  T.assert key?, "found a key'"
  for msg,i in o.encrypted
    await do_message { armored : msg.ciphertext, keyfetch : km }, defer err, out
    T.no_error err
    T.equal out.length, 1, "got 1 literal data packet"
    lit = out[0]
    T.equal lit.data.toString('utf8'), msg.plaintext, "plaintext came out ok"
    signer = lit.get_data_signer()
    T.assert not(signer?), "we not were signed"
    T.waypoint "decrypted msg #{i}"
  for msg,i in o.signcrypted
    await do_message { armored : msg.ciphertext, keyfetch : km }, defer err, out
    T.no_error err
    T.equal out.length, 1, "got 1 literal data packet"
    lit = out[0]
    T.equal lit.data.toString('utf8'), msg.plaintext, "plaintext came out ok"
    T.waypoint "decrypted/verified msg #{i}"
    signer = lit.get_data_signer()
    T.assert signer?, "we were signed"
  cb()

#=================================================================

exports.elgamal_round_trip = (T,cb) ->
  o = planck
  opts =
    msg : o.quotes[0]
    signing_key : km.find_signing_pgp_key()
    encryption_key : km.find_crypt_pgp_key()
  await burn opts, defer err, asc
  T.no_error err
  await do_message { armored : asc, keyfetch : km }, defer err, out
  T.no_error err
  lit = out[0]
  T.assert lit?, "got one out packet"
  T.equal lit.data.toString('utf8'), o.quotes[0], "got equality"
  T.assert lit.get_data_signer()?, "message was signed"
  cb()

#=================================================================

