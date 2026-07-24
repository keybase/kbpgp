
C = require('./const').openpgp.symmetric_key_algorithms
triplesec = require 'triplesec'
{AES} = triplesec.ciphers
{CAST5} = require './openpgp/cast5'
{SlicerBuffer} = require './openpgp/buffer'
{WordArray} = triplesec
{uint_to_buffer} = require './util'
{ecc_pkcs5_unpad_data} = require './pad'
ct = require './consttime'

allowed_ciphers = [C.AES128, C.AES192, C.AES256, C.CAST5]

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

exports.import_key_pgp_ct = import_key_pgp_ct = (valid_msg, msg, random_key, pkcs5_padding = false) ->
  ret = err = null

  # We are going to iterate all allowed ciphers, but only store selected_algo
  # and selected_key for the cipher that matches (and validates checksum
  # etc.). This is to ensure import_key_pgp_ct is constant time.

  selected_algo = C.AES256
  selected_key = random_key
  found_cipher = 0

  for c in allowed_ciphers
    cipher = get_cipher c
    algo = ct.read_byte msg, 0
    # If the msg itself is invalid, mark the candidate as invalid but still
    # continue with the checks here.
    valid = ct.normalize valid_msg
    valid &= ct.eq_int algo, c
    # Read key (fill with 0 if buffer is too short)
    key = Buffer.alloc(cipher.key_size)
    for i in [0...cipher.key_size]
      key[i] = ct.read_byte msg, i + 1
    # Check the checksum.
    checksum = ct.read_uint16_be msg, 1 + cipher.key_size
    valid &= ct.eq_int checksum2(key), checksum

    offset = 1 + cipher.key_size + 2
    if pkcs5_padding
      # Check pkcs5_padding if it's been asked for.
      valid &= ct.normalize(msg.length >= offset)
      # ecc_pkcs5_unpad_data returns null if padding is correct.
      valid &= ct.eq_int ct.normalize(ecc_pkcs5_unpad_data(msg, offset)), 0
    else
      # If there is junk at the end, key is invalid.
      valid &= ct.eq_int msg.length, offset

    selected_algo = ct.select_int valid, c, selected_algo
    selected_key = ct.select_buffer valid, key, selected_key
    found_cipher = ct.select_int valid, 1, found_cipher

  # Cipher is guaranteed to exist because we enumerated all possible candidates.
  # So get_cipher shall not throw.
  cipher = get_cipher selected_algo

  # This slice is not constant time, but at this point `cipher` has been
  # sanitized, so we are either slicing with a valid key_size or fixed
  # fallback size.
  key = selected_key[0...cipher.key_size]

  [!!found_cipher, new cipher.klass WordArray.from_buffer key]

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
    Buffer.from([ algo_id ]),
    key,
    uint_to_buffer(16,csum)
  ]

