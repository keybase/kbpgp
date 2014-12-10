
{RSA} = require '../../lib/rsa'
{SRF} = require '../../lib/rand'
{ElGamal} = require '../../lib/elgamal'
{bufeq_secure} = require '../../lib/util'
{KeyManager} = require '../../'

#=========================================================================

exports.test_hide_rsa = (T,cb) ->
  await setTimeout defer(), 10
  nbits = 1024
  await RSA.generate { nbits }, defer err, key
  T.no_error err
  await setTimeout defer(), 10
  T.waypoint "generated #{nbits} bit key!"
  T.equal key.nbits(), nbits, "the right number of bits"

  await SRF().random_bytes 64, defer data
  await key.pad_and_encrypt data, {}, defer err, ctext
  bl_orig = ctext.y().bitLength()
  y_orig = ctext.y()
  T.waypoint "Encrypted a random payload"
  T.no_error err

  await ctext.hide { key, max : 8192, slosh : 64 }, defer err
  T.no_error err

  lo  = 8192 + 48 # shouldn't be any fewer bits than this
  hi  = 8192 + 64 # upper max
  T.assert (ctext.y().bitLength() >  lo), "Got more than #{lo} bits in output"
  T.assert (ctext.y().bitLength() <= hi), "Got at most #{hi} bits in output"

  for_wire = ctext.output()
  ctext2 = RSA.parse_output for_wire

  ctext2.find { key }
  T.equal ctext2.y().bitLength(), bl_orig, "the right bitlength after finding"
  T.assert ctext2.y().equals(y_orig), "we got the right y back"

  await key.decrypt_and_unpad ctext2, {}, defer err, plaintext
  T.no_error err
  T.assert bufeq_secure(plaintext, data), "output was same as input"

  cb()

#=========================================================================

elgamal = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQG7BFN7jx8RBADSEjexey1cHCYjAH95iSjsmnpWiliJng934+u1P5pJWcGMrMtT
9qyHMFIR/WmTFx/iwVAPJP5oif09KpXUeY/uHlU0LAhOKwtqAMznB+C2I3UKLqeX
uDP/A7zJH7KAF5P9wlI2PQ8XyhU91XqIZKnTmkXFxhLMRGrWDEX9UU2W6wCgsHqa
SqNnUqqAZOc3aKNemaQ+FX0EAJOmOKyVmDxbev+fh5sXifQJQc8mhA6Ei3d0EtKt
BoFqBGmBdpzRRtfwiDCGWPM8HG347Rx4RjZGXnOifayJ/iolBxK55oLzRQ+JUw/X
y3PyyEFQUl5a0e8LrAR04JnkktFsCoX1NxWXDPhg36zsEnuNlHjlDvZmoU4ZqfdT
Ius5BACpyyuyx8DDivsUo/1UvwiybvhJNfOfH0F/38RSDuVf/IifvOgtU1w62/Wl
O63J9MS1athyA5ZEq4I6jtRhpoguV0migOp6FCUIo3n3sGV+Zrom2tCl5le8tXF2
RsNN+Y796va4/JqfrrOni32UhD2tmOepxqaqI/2jfoVb0fdM+AAAoKOjpec/nCt5
TZHnVafOwHQ/aIQbCvq0DUhpZGluZyBUZXN0ZXKIYgQTEQoAIgUCU3uPHwIbAwYL
CQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQz4r7Sm7VGeE7jACeJh4UDGJUncTw
Zw8F8i/AaPK/IuoAoJKDbl5+/rLNRj45i5eM7FvHiI6snQEyBFN7jx8QBADSkv91
ZVy/2xMSujVa3hPafAS5jHpom9g4d28S+PTJPltR0indEA0BpSW33APBmlt5o1ZA
ZiTxAjXtyXlBQRiq0XmzKsocapEfGK3ZA/dAuBCE+nNP2G5fftfIOZXCBJNeUswW
ftKd4DS19E+2LkUn8buxTaW68LFl8RlPEOGOMwADBQP+Osv8VcuNTanLorZD4MqX
JIP6vag2crySF8wg1lauGjfejGScThln43dBpeLRKXaIcnRxXn3smRSvLFxXNt1l
mgnsZ1WIjxTHKekYnle+9bmPLJkgadsUUiSca4olv4OLDrBlpBc8WhcAmtoX1gqQ
m1nmU6x6awbRTCjNQXwYNfIAAPkBhOwiwjoD/Xf1oXxPd5XPSxA5HqOW0DkjcmFX
yGDYuRA1iEkEGBEKAAkFAlN7jx8CGwwACgkQz4r7Sm7VGeGfxwCeJRNE8f4JWahQ
qoeWsoOD8OabWgMAn1HkSOvbgTWsvGFldFwR800VfwaZ
=NI6H
-----END PGP PRIVATE KEY BLOCK-----
"""

exports.test_hide_elgamal = (T,cb) ->
  await setTimeout defer(), 10
  await KeyManager.import_from_armored_pgp { raw : elgamal }, defer err, pubkey
  T.no_error err
  await pubkey.unlock_pgp { passphrase : '' }, defer err
  T.no_error err
  key = pubkey.find_crypt_pgp_key().key
  await SRF().random_bytes 64, defer data
  await key.pad_and_encrypt data, {}, defer err, ctext
  c_mpis_orig = ctext.c()
  await ctext.hide { key, max : 4096 , slosh : 64 }, defer err

  T.no_error err

  lo  = 4096 + 48 # shouldn't be any fewer bits than this
  hi  = 4096 + 64 # upper max
  for c_mpi in ctext.c()
    T.assert (c_mpi.bitLength() >  lo), "Got more than #{lo} bits in output"
    T.assert (c_mpi.bitLength() <= hi), "Got at most #{hi} bits in output"

  for_wire = ctext.output()
  ctext2 = ElGamal.parse_output for_wire

  ctext2.find { key }
  for c_mpi,j in ctext2.c()
    T.assert c_mpis_orig[j].equals(c_mpi), "we got c_#{j} back"

  await key.decrypt_and_unpad ctext2, {}, defer err, plaintext
  T.no_error err
  T.assert bufeq_secure(plaintext, data), "output was same as input"

  T.no_error err
  cb()
