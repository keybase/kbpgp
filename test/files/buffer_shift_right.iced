
{buffer_shift_right} = require '../../lib/bn'
{bufeq_fast} = require '../../lib/util'

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


