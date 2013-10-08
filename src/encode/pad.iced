
{SHA512} = require '../hash'
C = require('../const').openpgp
{nbs} = require '../bn'
{buffer_to_ui8a,bufeq_secure} = require '../util'

#====================================================================

hash_headers = 
  SHA1 : [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]
  SHA224 : [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1C]
  SHA256 : [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
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
    i++ if v.readUInt8(i) is 0
    if v.readUInt8(i++) isnt 1
      err = new Error "Didn't get two-byte header 0x00 0x01"
    else 
      (i++ while i < v.length and (v.readUInt8(i) is 0xff))
      if i >= v.length or v.readUInt8(i) isnt 0
        err = new Error "Missed the 0x0 separator"
      else
        i++
        header = hash_headers[hasher.algname]
        if not bufeq_secure(new Buffer(header), v[i...(header.length+i)])
          err = new Error "missing ASN header for #{hasher.algname}"
        else
          i += header.length
          h = v[i...]
          if h.length isnt hasher.output_length
            err = new Error "trailing garbage in signature"
          else
            ret = h
  [err, ret]


#====================================================================

