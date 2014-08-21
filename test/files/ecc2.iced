{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
km = null
top = require '../../lib/main'

#=================================================================

exports.import_ecc_key_with_private_gen_by_google_e2e_1 = (T, cb) ->

  key = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Charset: UTF-8
Version: End-To-End v0.3.1338

xf8AAAB3BFOsKbATCCqGSM49AwEHAgMEhEKmGdZix3AbyoAVe6Bd4WZE8jGVUbKh
NCaDyKaE7rKk5JZa2hIyaJN8wEOIJ3hWgPBTK13n+zvrllSNRz9+7gAA/iCIKxxK
M3Q81TyXQASN345AWSmjb/evQfwFBreq1M57D0DN/wAAABI8dGhlbWF4QGdtYWls
LmNvbT7C/wAAAGYEEBMIABj/AAAABYJTrCmw/wAAAAmQh6GhxI25BWcAAEphAQCY
dab0CXAU1JCEUDegFih6n1LJjlQ8rr9jkdkplfZKyAD/Z/204vz6ICHYB8rhHOC6
127D8KHdLYaR8KKNPEDw6m/H/wAAAHsEU6wpsBIIKoZIzj0DAQcCAwRiCoBfuydu
cp3FChW9Q4Yz6cXU2okTyGv2hHsnQ2P5tilLSBp2cv4TnV4LIawNsP+gsesoXSln
hFb+sAdaTvwxAwEIBwAA/AvHI+wsE9cFyxe6tHePCa+/KCrRia6Jz9VYMkTJKxcD
DyjC/wAAAGYEGBMIABj/AAAABYJTrCmw/wAAAAmQh6GhxI25BWcAAASlAP985Usk
lzOHK4VuqatRW35xBICiymeQX+aDXbU/6OL1cwD7Bj+TmwRDQe9b3yAV8ktaZM/L
3Uc+HTz2Cp9wtwSPXXfG/wAAAFIEU6wpsBMIKoZIzj0DAQcCAwSEQqYZ1mLHcBvK
gBV7oF3hZkTyMZVRsqE0JoPIpoTusqTkllraEjJok3zAQ4gneFaA8FMrXef7O+uW
VI1HP37uzf8AAAASPHRoZW1heEBnbWFpbC5jb20+wv8AAABmBBATCAAY/wAAAAWC
U6wpsP8AAAAJkIehocSNuQVnAABKYQEAmHWm9AlwFNSQhFA3oBYoep9SyY5UPK6/
Y5HZKZX2SsgA/2f9tOL8+iAh2AfK4Rzgutduw/Ch3S2GkfCijTxA8Opvzv8AAABW
BFOsKbASCCqGSM49AwEHAgMEYgqAX7snbnKdxQoVvUOGM+nF1NqJE8hr9oR7J0Nj
+bYpS0gadnL+E51eCyGsDbD/oLHrKF0pZ4RW/rAHWk78MQMBCAfC/wAAAGYEGBMI
ABj/AAAABYJTrCmw/wAAAAmQh6GhxI25BWcAAASlAPsFvd0AeDmF2wBJd4l1g0oV
TfplxTTTYO6DJP5McmTtKwD+P7WgGuy0IssdwD7bU//zlOvl9nyztxojitGtDtT2
CNU=
=TRLE
-----END PGP PRIVATE KEY BLOCK-----"""

  await KeyManager.import_from_armored_pgp { raw : key }, defer err, tmp, warnings
  T.no_error err
  T.assert tmp?, "a key manager returned"
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  km = tmp
  cb()

#=================================================================

exports.unlock_private = (T,cb) ->
  T.assert km.has_pgp_private(), "has a private key"
  await km.unlock_pgp { passphrase : '' }, defer err
  T.no_error err
  cb()

#=================================================================

exports.decrypt_ecdh_1 = (T,cb) ->

  msg = """
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

hH4DZen/wXRK1k0SAgMEMaeSZiHn2zlYnn57aUN7R6RLg6grrfgMlDya4c3LeLNT
TKAuSg6s0Bdl21QQKWsfZEkRLPbZIXuP4vE5jwWdCzCjit+3Z8HZRz4zORTAQ+jI
M/h1V3bwMIKarlrQLkBcT2nkMlk55EP9CXuZ+ch/y3rSQQFR4GaqfDUsmHnI7jdC
tIS8mMwehxu5u2THLSteUgrfT1HByfbq2Qt33C+ESezeW8YPSdbMb9b0NfSkpWRO
pvdU
=TbII
-----END PGP MESSAGE-----
  """
  await do_message { armored : msg, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal msg[0].toString(), "hello world\n", "got the right plaintext"
  cb()

#=================================================================

exports.roundtrip_ecdh_1 = (T,cb) ->

  plaintext = """
The Aquarium is gone. Everywhere,
giant finned cars nose forward like fish;
a savage servility
slides by on grease.
"""
  await burn { msg : plaintext, encrypt_for : km }, defer err, aout, raw
  T.no_error err
  await do_message { armored : aout, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "roundtrip worked!"
  cb()

#=================================================================

roundtrip_sig_crypt = (T,km,cb) ->
  plaintext = """
The Aquarium is gone. Everywhere,
giant finned cars nose forward like fish;
a savage servility
slides by on grease.
"""
  await burn { msg : plaintext, encrypt_for : km, sign_with : km }, defer err, aout, raw
  T.no_error err
  await do_message { armored : aout, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "roundtrip worked!"
  T.assert (msg[0].get_data_signer()?), "was signed!"
  sign_fp = msg[0].get_data_signer().sig.key_manager.get_pgp_fingerprint()
  start_fp = km.get_pgp_fingerprint()
  T.equal sign_fp.toString('hex'), start_fp.toString('hex'), "signed by the right person"
  cb()

#======================================================================

exports.roundtrip_sig_crypt_1 = (T,cb) -> roundtrip_sig_crypt T, km, cb

#=================================================================

exports.generate_and_roundtrip = (T,cb) ->
  await KeyManager.generate_ecc { userid : "test@test.cc" }, defer err, km2
  T.no_error err
  await km2.sign {}, defer err
  T.no_error err
  await km2.export_pgp_private { passphrase : '' }, defer err, msg
  T.no_error err
  await roundtrip_sig_crypt T, km2, defer()
  cb()

#=================================================================

exports.generate_export_import = (T,cb) ->
  await KeyManager.generate_ecc { userid : 'test@test.io' }, defer err, km3
  T.no_error err
  await km3.sign {}, defer err
  T.no_error err
  passphrase = "goat dog bird"
  plaintext = "this be the verse"
  await top.box { msg : plaintext, encrypt_for : km3, sign_with : km3  }, defer err, aout, raw
  T.no_error err
  await km3.export_private { p3skb : true, passphrase }, defer err, ex
  T.no_error err
  await KeyManager.import_from_p3skb { raw : ex }, defer err, km4
  T.no_error err
  await km4.unlock_p3skb { passphrase }, defer err
  T.no_error err
  await top.unbox { armored : aout, keyfetch : km4 }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "roundtrip worked!"
  cb()

#=================================================================

