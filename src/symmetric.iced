
C = require('./const').openpgp.symmetric_key_algorithms
triplesec = require 'triplesec'
{AES} = triplesec.ciphers
{CAST5} = require './openpgp/cast5'
{SlicerBuffer} = require './openpgp/buffer'
{WordArray} = triplesec
{uint_to_buffer} = require './util'

exports.get_cipher = get_cipher = (n) ->
  switch n
    when C.AES128 then { klass : AES, key_size : 16 }
    when C.AES192 then { klass : AES, key_size : 24 }
    when C.AES256 then { klass : AES, key_size : 32 }
    when C.CAST5  then { klass : CAST5, key_size : CAST5.keySize }
    else
      throw new Error "unknown cipher: #{n}"

exports.checksum2 = checksum2 = (buf) ->
  res = 0
  for i in [0...buf.length]
    res = ((res + buf.readUInt8(i)) & 0xffff)
  res

exports.import_key_pgp = import_key_pgp = (msg) ->
  sb = new SlicerBuffer msg
  ret = err = null
  cipher = get_cipher sb.read_uint8()
  key = sb.read_buffer cipher.key_size
  checksum = sb.read_uint16()
  throw new Error "Junk at the end of input" unless sb.rem() is 0
  throw new Error "Checksum mismatch" unless checksum2(key) is checksum
  new cipher.klass WordArray.from_buffer key

exports.export_key_pgp = export_key_pgp = (algo_id, key) ->
  csum = checksum2 key
  Buffer.concat [
    new Buffer([ algo_id ]),
    key,
    uint_to_buffer(16,csum)
  ]

