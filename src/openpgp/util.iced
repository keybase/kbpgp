C = require '../const'

#=========================================================

#
# Equivalent to this monstrosity you might see in OpenPgpJS:
#
#  var d = new Date();
#  d = d.getTime()/1000;
#  var timePacket = String.fromCharCode(Math.floor(d/0x1000000%0x100)) + String.fromCharCode(Math.floor(d/0x10000%0x100)) + String.fromCharCode(Math.floor(d/0x100%0x100)) + String.fromCharCode(Math.floor(d%0x100));
#
exports.make_time_packet = (d) ->
  d or= Math.floor(Date.now()/1000)
  b = new Buffer 4
  b.writeUInt32BE d, 0
  b

#=========================================================

exports.calc_checksum = calc_checksum = (text) ->
  ret = 0
  for i in [0...text.length]
    ret = (ret + text.readUInt8(i)) % 65536
  ret

#=========================================================

# Encode a v4 packet length l.  Use the smallest available
# encoding unless the 'five_byte' flag is specified, and in that case,
# use the full 5-byte expansion
exports.encode_length = encode_length = (l, five_byte= false) ->
  ret = null
  if l >= 8384 or five_byte
    ret = new Buffer 5
    ret.writeUInt8 0xff, 0
    ret.writeUInt32BE l, 1
  else if l < 192 
    ret = new Buffer 1
    ret.writeUInt8 l, 0
  else if l >= 192 and l < 8384
    ret = new Buffer 2
    ret.writeUInt16BE( ((l - 192) + (192 << 8 )), 0)
  ret

#=========================================================

exports.ops_to_keyflags = ops_to_keyflags = (ops) ->
  out = 0
  if (ops & C.ops.encrypt) then out |= C.openpgp.key_flags.encrypt_comm
  if (ops & C.ops.decrypt) then out |= C.openpgp.key_flags.encrypt_comm
  if (ops & C.ops.verify)  then out |= C.openpgp.key_flags.sign_data
  if (ops & C.ops.sign)    then out |= C.openpgp.key_flags.sign_data
  return out

#=========================================================
