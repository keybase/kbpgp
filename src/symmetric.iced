
C = require('./const').openpgp.symmetric_key_algorithms
triplesec = require 'triplesec'
{AES} = triplesec.ciphers
{CAST5} = require './openpgp/cast5'
{SlicerBuffer} = require './openpgp/buffer'
{WordArray} = triplesec
{uint_to_buffer} = require './util'
{ecc_pkcs5_unpad_data} = require './pad'

exports.get_cipher = get_cipher = (n) ->
  n or= C.AES256
  ret = switch n
    when C.AES128 then { klass : AES, key_size : 16 }
    when C.AES192 then { klass : AES, key_size : 24 }
    when C.AES256 then { klass : AES, key_size : 32 }
    when C.CAST5  then { klass : CAST5, key_size : CAST5.keySize }
    else
      throw new Error "unknown cipher: #{n}"
  ret.type = n
  return ret

exports.checksum2 = checksum2 = (buf) ->
  res = 0
  for i in [0...buf.length]
    res = ((res + buf.readUInt8(i)) & 0xffff)
  res

exports.import_key_pgp = import_key_pgp = (msg, pkcs5_padding = false) ->
  sb = new SlicerBuffer msg
  ret = err = null
  cipher = get_cipher sb.read_uint8()
  key = sb.read_buffer cipher.key_size
  checksum = sb.read_uint16()

  # First check the checksum.
  # Next, check the key remainder, and be strict about no trailing junk,
  # and we must apply pkcs5_padding if it's been asked for, to ensure the
  # mod 8 requirement at the very least.
  err = if checksum2(key) isnt checksum then new Error "Checksum mismatch" 
  else if pkcs5_padding then ecc_pkcs5_unpad_data msg, sb.offset()
  else if not sb.rem() then null
  else new Error "Junk at the end of input"

  throw err if err?

  new cipher.klass WordArray.from_buffer key

exports.export_key_pgp = export_key_pgp = (algo_id, key) ->
  csum = checksum2 key
  Buffer.concat [
    new Buffer([ algo_id ]),
    key,
    uint_to_buffer(16,csum)
  ]

