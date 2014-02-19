
{nbi,bn_from_left_n_bits,buffer_shift_right} = require '../../lib/bn'
{bufeq_fast} = require '../../lib/util'

#==========================================================

exports.test_buffer_shift_right = (T,cb) ->
  byte_string = "70fa4a33c12271aa61863380a1b09704d6b15b12a268273d15f1b53fb18eebd7654b20540e394540"
  bufs = for i in [0...byte_string.length] by 8
    new Buffer(byte_string[i...(i+8)], 'hex')

  # Make sure all number are less than 2^31 just so we don't have to deal with sign bits
  for buf in bufs
    b = buf.readUInt8(0)
    if b >= 0x80
      buf.writeUInt8(b - 0x80, 0)

  for buf,j in bufs
    for shift in [0...15]
      i = (buf.readUInt32BE(0) >> shift)
      b2 = new Buffer [0,0,0,0]
      b2.writeUInt32BE(i,0)
      b3 = buffer_shift_right(new Buffer(buf), shift)

      # We need to add a leading '0' back so that we still have
      # 4 bytes of data, so compare works to a standard 32-bit integer
      b3 = Buffer.concat [ Buffer(0 for [0...(shift >> 3)] ), b3 ]
      T.assert bufeq_fast(b3,b2), "Buffer #{j}, shift=#{shift}"

  cb()

#==========================================================

exports.test_mpi_from_left_n_bits = (T,cb) ->
  raw_ints = [
    "210aac1bc5f4e8965caa06902d7b13e081656534bc4e64a48f327f89f766f3c356a46a4f94ed6a07"
    "650774e123cbd130ba387a282f0df84479ca8d4b3509fec1769df032c4841fd96268729df7a9120a"
    "b0ae53ebddf51a6d7b3a9d5e99f22e5ca2a88de6ed1af44928dce63588fd562462896a80d217c908"
    "6b3d1728e0f299e756d235bc296b4c36badf48df69e8b7983873109ec285bdd5d5bd7814dd634509"
    "ad4857355a53bad83159a3bbdba9cde32e0b7fd8d0393bda057a4e5f7c41cba22cb99d986f36b4b6"
    "c2f2fcfa41a938076313be44df178b748a78dcec8c546ddb34ed2da393d6d030d0074ea941a8337a"
    "f480f51f73e81e8b832580ca7e42c74cbd42e5e6d57d93eed28f54abbfe8b16e410c8d2c46b78f4c"
    "abca8d2300a434503d687da1e73aafdc89063fdb3388c5f86a47015d68a22be5491062368c2dd5b4"
    "a741193385d070726399683c355048791197f880c7560abf9fd15f0b86f8b4ee6d04b6329c2e7c0d"
    "8a7f6f1a51778e3da036eed8137ec8811d7f99b466dcba8721a07007cacf5e5215a7984c633d972e"
  ]
  nbits = raw_ints[0].length*4
  for ri,j in raw_ints
    for shift in [0...39]
      buf = new Buffer ri, 'hex'
      i1 = nbi().fromBuffer buf
      i2 = i1.shiftRight shift
      i3 = bn_from_left_n_bits(buf, nbits - shift)
      T.assert i2.equals(i3), "int #{j}, shift #{shift}"
  cb()

#==========================================================

