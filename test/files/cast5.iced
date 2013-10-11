{CAST5} = require '../../lib/openpgp/cast5'
{WordArray} = require 'triplesec'
{encrypt,decrypt} = require '../../lib/openpgp/cfb'

buf_to_words = (b) -> (WordArray.from_buffer b).words
words_to_buf = (w) -> (new WordArray w).to_buffer()

exports.rfc_2144_B1 = (T,cb) ->
  key = new Buffer "0123456712345678234567893456789A", "hex"
  plaintext = new Buffer "0123456789ABCDEF", "hex"
  ciphertext = new Buffer "238B4FE5847E44B2", "hex"

  cast5 = new CAST5 WordArray.from_buffer key
  out_wa = cast5.encryptBlock buf_to_words plaintext
  out_buf = words_to_buf out_wa
  T.equal out_buf.toString('hex'), ciphertext.toString('hex'), 'encryption worked'
  pt2_wa = cast5.decryptBlock out_wa
  pt2_buf = words_to_buf pt2_wa
  T.equal plaintext.toString('hex'), pt2_buf.toString('hex'), 'decryption worked'
  cb()

exports.cfb = (T,cb) ->
  key = new Buffer "583d18c32d8857a627ea3e86d6feada8", "hex"
  iv = new Buffer 'fe40e836b0e9b193', 'hex'
  dat = "i8xDA+KyfRK5q6c2h5YHgt+6LQOJsQB2TP98obYZJO8DAR02EyJPRTuA4sVsOJQGbbzC+6mYhAwYT2w21Qx9rfbH85kw6M/68O8WGTqb5cH418+Ff/jK9211+a4CQGJTjZKCUkRTWB08mDiniFp3c5ohkFjJ/542DR31PyFr7Qc="
  plaintext = new Buffer dat, "base64"
  ciphertext = encrypt { block_cipher_class : CAST5, key, iv, plaintext }   
  pt2 = decrypt { block_cipher_class : CAST5, key, iv, ciphertext }
  T.equal pt2.toString('base64'), dat, "in and out with cfb"
  cb()
