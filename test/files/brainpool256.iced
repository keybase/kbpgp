{KeyManager} = require '../../lib/main'
{do_message} = require '../../lib/openpgp/processor'
{burn} = require '../../lib/openpgp/burner'
km = null
top = require '../../lib/main'

#=================================================================

exports.import_brainpool256_key_with_private_gen_by_gnupg = (T, cb) ->

  key = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2

lKYEVcxn0RMJKyQDAwIIAQEHAgMEkY9pSwWAp3Bk8DQxMyuDN2thQ5Y/fRNIIk6G
owrD06dTUnUOq3eKMQ4Mg4c8mV9FkdnsWA8L4FM+8xhcorOdGf4HAwI70WABShGE
ftGuf1prbz9Hln8rl8+HKc+IWfmgakiINbFELJ1dZURzaRkzhL+oOrQWwc/KKsJy
f9la0G/Ck7EU3MoDPyCzwW8ZarkeQoUytCdUZXN0IEJyYWlucG9vbCAyNTYgPDI1
NkBicmFpbnBvb2wudGVzdD6IeQQTEwgAIQUCVcxn0QIbAwULCQgHAgYVCAkKCwIE
FgIDAQIeAQIXgAAKCRC4o/ZJ5bQjQAwoAP9YQaB1HwUVn3BWl+b2mVBZQUu1U/Kk
CPz2f6r4wF3H4gD6Ar44Id/Mh9ByqKWYkgwLaZDDXmORhLydadOixnwMJsqcqgRV
zGfREgkrJAMDAggBAQcCAwQSKhixu8ufOKnK41hcFTJKiaLvBuO3VXBJE8InsrS+
UDlOW/RQ4vws86XaToEqXVvgL+5mcqHHxXhb4SiwMWJkAwEIB/4HAwJ+sBNx0dCj
F9HF00efDQu+WV56MDTh/P3Tf5vv4mZw1CDlfn8m0LmHl5srv63h03phhSHACF3F
9GjFMBo7b8H7dJigUs1GlV5r6ieWUajNiGEEGBMIAAkFAlXMZ9ECGwwACgkQuKP2
SeW0I0BwgQD+L4N7x0SzK3XL9LrdjrRRgxE+VltmbwyYeo1Mf3NMoVIA/2HpdSnU
reAOXD9JZZpDA0LB2zCMNGs6wIGpOvoovhAF
=XPDS
-----END PGP PRIVATE KEY BLOCK-----"""

  await KeyManager.import_from_armored_pgp { raw : key }, defer err, tmp, warnings
  T.no_error err
  T.assert tmp?, "a key manager returned"
  T.assert (warnings.warnings().length is 0), "didn't get any warnings"
  km = tmp
  cb()

#=================================================================

exports.unlock_private_brainpool256 = (T,cb) ->
  T.assert km.has_pgp_private(), "has a private key"
  await km.unlock_pgp { passphrase : '256' }, defer err
  T.no_error err
  cb()

#=================================================================

exports.decrypt_brainpool256 = (T,cb) ->

  msg = """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

hH4DdGOace5sY7kSAgMEUyoWcn7EmC1FjW0ni2I2ODQrNhrq/X4BpJqYDNhveN2p
XRTKdcqXOW6JpEwBcx4UyyYJfhFZQfZvOfJhGCOVQzA4lmU2GBSXqy+iXvJoa+ez
q6BJH3TC8H2w8i8A8eVj9MXTH7n5ByiVfT1/k4GrZ4nSYQFpofUxQCyqxJdpQoWf
Mw1BjhCD67CTVAfVrYIjEdeJOYLESEnWhYq8MwLOFVDlQ1m7X+NVCET5ka4LgrAB
coAn98oW6OHMPuxwCJl2Vu/F2XyNGiKne+QEso794LCv+iM=
=GyPd
-----END PGP MESSAGE-----"""
  await do_message { armored : msg, keyfetch : km }, defer err, msg
  T.no_error err
  T.equal msg[0].toString(), "hello world (Brainpool 256)\n", "got the right plaintext"
  cb()

#=================================================================

exports.roundtrip_brainpool256 = (T,cb) ->

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

roundtrip_sig_crypt_brainpool256 = (T,km,cb) ->
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

exports.roundtrip_sig_crypt_brainpool256 = (T,cb) -> roundtrip_sig_crypt_brainpool256 T, km, cb

#=================================================================
