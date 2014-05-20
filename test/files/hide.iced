
{RSA} = require '../../lib/rsa'
{SRF} = require '../../lib/rand'
{bufeq_secure} = require '../../lib/util'

exports.test_hide_1024 = (T,cb) ->
  await setTimeout defer(), 10
  nbits = 1024
  await RSA.generate { nbits }, defer err, key 
  T.no_error err
  await setTimeout defer(), 10
  T.waypoint "generated #{nbits} bit key!"
  T.equal key.nbits(), nbits, "the right number of bits"

  await SRF().random_bytes 64, defer data
  await key.pad_and_encrypt data, defer err, ctext
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

  await key.decrypt_and_unpad ctext2, defer err, plaintext
  T.no_error err
  T.assert bufeq_secure(plaintext, data), "output was same as input"

  cb()

