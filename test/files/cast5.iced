{CAST5} = require '../../src/cast5'
{WordArray} = require 'triplesec'

exports.rfc_2144_B1 = (T,cb) ->
  key = new Buffer "0123456712345678234567893456789A", "hex"
  plaintext = new Buffer "0123456789ABCDEF", "hex"
  ciphertext = new Buffer "238B4FE5847E44B2", "hex"

  cast5 = new CAST5 WordArray.from_buffer key
  out_wa = cast5.encrypt WordArray.from_buffer plaintext
  out_buf = out_wa.to_buffer()
  T.equal out_buf.toString('hex'), ciphertext.toString('hex'), 'encryption worked'
  pt2_wa = cast5.decrypt out_wa
  pt2_buf = pt2_wa.to_buffer()
  T.equal plaintext.toString('hex'), pt2_buf.toString('hex'), 'decryption worked'
  cb()
