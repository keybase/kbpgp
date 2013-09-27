
{SHA512} = require './hash'
C = require('./const').openpgp
{nbs} = require './bn'

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
exports.emsa_pcks1_encode = emsa_pcks1_encode = (data, len, opts = {}) ->
  hash = opts.hash or SHA512
  console.log hash.algname
  headers = hash_headers[hash.algname]
  n = len - headers.length - 3 - hash.output_length

  chars = [ 0x00, 0x01 ].concat(0xff for i in [0...n]).concat [0x00].concat headers
  buf = Buffer.concat [ new Buffer(chars), hash(data) ]

  # We have to convert to a Uint8 array since the JSBN library internally
  # uses A[.] rather than A.readUint8(.)...
  nbs(new Uint8Array(buf), 256)

#====================================================================