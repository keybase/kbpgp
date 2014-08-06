
{KeyManager,unbox} = require '../..'

msg = """
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

hQEMA9IPP7qcdOKdAQgAg0LpPALqQdo2LRNjms0ia4UVfQoplzzzdArHdc2WD/fN
wzANiv5lZ9FcTwK2+mc0hzqDwYi1y9F4CGzY82B3JyrI+zCp0yLdg79iG8EHhmxN
V9Qph7kpP4liRNZbJHILIdXJk3GYKlV6paLmLvmD4LNZr/I/uvzLa+EIpBXwRvyd
aejfiMd1hl8Y9BSnSNWkLZ2VLJcUkXMPwuxbdjtOZPe3ecHADt87d2l2zwXMb4iF
z03tPmnoIPzsgi+fRofOl3JMQ8B0FCv6P+cSpVnY10b4yaGUR2NiaT3OgjlqC80t
8C2XtmbBtslSyXyYAqCOmB2MSPKC+HOJ5YbEdeaXC9KBATe0LdB2rih22QwzA4al
kZ6GN+Np3Bc6riLzlj2ESx0rdI5ZfZZj9hcUlYR6fHHeVIuaRF1Lrti5HnQeFCof
qLDlTgLAYfTwrl5QesCnO1+OZENM2AiwlNB30yIu2t2xwUkP3niFY5K2m2NvaEGt
NQYTWstWXg9yKY+5AWWZktqC
=P3pq
-----END PGP MESSAGE-----
"""

key = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

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
=rvNA
-----END PGP PRIVATE KEY BLOCK-----
"""

passphrase = "asdf"
km = null

#================================

exports.init = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored: key }, defer err, tmp
  T.no_error err
  km = tmp
  await km.unlock_pgp { passphrase }, defer err
  T.no_error err
  cb()

#================================

exports.unzip = (T,cb) ->
  await unbox { armored : msg, keyfetch : km }, defer err, dat
  T.no_error err
  T.assert (dat[0]?.toString()?.indexOf('Crowds of men and women') is 0)
  cb()

#================================
#  buf = Buffer.concat [ new Buffer([0x78,0x9c]), buf ]
#  try
#    console.log "inflating..."
#    ret = new Buffer pako.inflate buf
#  catch e
#    err = e
#
