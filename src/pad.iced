{SHA512} = require './hash'
C = require('./const').openpgp
{nbs} = require './bn'
{buffer_to_ui8a,bufeq_secure} = require './util'
{SRF} = require './rand'

#====================================================================

hash_headers = 
  MD5 : [0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,0x04,0x10]
  SHA1 : [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]
  SHA224 : [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1C]
  SHA256 : [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
  SHA384 : [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30]
  SHA512 : [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40]

#====================================================================

#
# create a EMSA-PKCS1-v1_5 padding (See RFC4880 13.1.3)
# @param {function} algo Hash algorithm type used
# @param {Buffer} data Data to be hashed
# @param {number} keylength Key size of the public mpi in bytes
#      XXXX - question, should this be rounded up or down!??!?!
# @returns {Buffer} Hashcode with pkcs1padding as string
#
exports.emsa_pkcs1_encode = emsa_pkcs1_encode = (hashed_data, len, opts = {}) ->
  hasher = opts.hasher or SHA512  
  headers = hash_headers[hasher.algname]
  n = len - headers.length - 3 - hasher.output_length

  buf = Buffer.concat [ 
    new Buffer([ 0x00, 0x01 ]),
    new Buffer(0xff for i in [0...n]),
    new Buffer([0x00]),
    new Buffer(headers),
    hashed_data ]

  # We have to convert to a Uint8 array since the JSBN library internally
  # uses A[.] rather than A.readUint8(.)...
  nbs(buffer_to_ui8a(buf), 256)

#====================================================================

exports.emsa_pkcs1_decode = emsa_pkcs1_decode = (v, hasher) ->
  err = ret = null
  i = 0
  if v.length < 2
    err = new Error "signature was way too short: < 2 bytes"
  else 
    if v.readUInt16BE(0) isnt 0x0001
      err = new Error "Sig verify error: Didn't get two-byte header 0x00 0x01"
    else 
      i = 2
      (i++ while i < v.length and (v.readUInt8(i) is 0xff))
      if i >= v.length or v.readUInt8(i) isnt 0
        err = new Error "Sig verify error: Missed the 0x0 separator"
      else
        i++
        header = hash_headers[hasher.algname]
        if not bufeq_secure(new Buffer(header), v[i...(header.length+i)])
          err = new Error "Sig verify error: missing ASN header for #{hasher.algname}"
        else
          i += header.length
          h = v[i...]
          if h.length isnt hasher.output_length
            err = new Error "Sig verify error: trailing garbage in signature"
          else
            ret = h
  [err, ret]

#====================================================================

eme_random = (n, cb) ->
  bytes = []
  while bytes.length < n
    diff = n - bytes.length
    await SRF().random_bytes diff, defer b
    for i in [0...diff]
      c = b.readUInt8(i)
      bytes.push c if c isnt 0
  cb new Buffer bytes

#--------------

# See
# 13.1.1. EME-PKCS1-v1_5-ENCODE
exports.eme_pkcs1_encode = (v, len, cb) ->
  ret = err = null
  if v.length > len - 11
    err = new Error "cannot encrypt message -- it's too long!"
  else
    n_randos = len - 3 - v.length
    await eme_random n_randos, defer PS
    buf = Buffer.concat [ 
      new Buffer( [0x00, 0x02] ),
      PS,
      new Buffer( [0x00] ),
      v
    ]
    ret = nbs(buffer_to_ui8a(buf), 256)
  cb err, ret

#====================================================================

exports.eme_pkcs1_decode = (v) ->
  err = ret = null
  if v.length < 12
    err = new Error "Ciphertext too short, needs to be >= 12 bytes"
  else if v.readUInt16BE(0) isnt 0x0002
    err = new Error "Failed to find expected header: 0x00 0x02"
  else
    i = 2
    (i++ while i < v.length and (v.readUInt8(i) isnt 0x0))
    if i >= v.length
      err = new Error "didn't get 0x00 seperator octet"
    else
      i++
      ret = v[i...]
  [err, ret]

#====================================================================

#
# From RFC-6637, Section 8
#   http://tools.ietf.org/html/rfc6637#section-8
#
#  "The result is padded using the method described in [PKCS5] 
#  to the 8-byte granularity."
#
exports.ecc_pkcs5_pad_data = (d) ->
  err = ret = null
  pad_len = 40 - d.length
  if pad_len < 0
    err = new Error "Pad underrun"
  else
    v = (pad_len for [0...pad_len])
    ret = Buffer.concat [ d, (new Buffer v) ]
  [err, ret]

#--------------

exports.ecc_pkcs5_unpad_data = (buf, data_len) ->
  err = null
  pad_len = buf.length - data_len
  if pad_len < 0
    err = new Error "Pad length was < 0; pad underrun"
  else if (buf.length % 8) isnt 0
    err = new Error "Padded data must be a multiple of 8 bytes long"
  else
    for i in [data_len...buf.length]
      if (c = buf.readUInt8(i)) isnt pad_len
        err = new Error "Got bad PKCS#5 pad character #{c} at position #{i}; wanted #{pad_len}"
        break
  err

#====================================================================

