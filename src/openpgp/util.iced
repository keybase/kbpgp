
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

exports.encode_length = encode_length = (l) ->
  ret = null
  if l < 192
    ret = new Buffer 1
    ret.writeUInt8 l, 0
  else if l >= 192 and l < 8384
    ret = new Buffer 2
    ret.writeUInt16BE( ((l - 192) + (192 << 8 )), 0)
  else
    ret = new Buffer 5
    ret.writeUInt8 0xff, 0
    ret.writeUInt32BE l, 1
  ret

#=========================================================

exports.bufeq_fast = (x,y) ->
  return false unless x.length is y.length
  for i in [0...x.length]
    return false unless x.readUInt8(i) is y.readUInt8(i)
  return true

#-----

exports.bufeq_secure = (x,y) ->
  ret = true
  if x.length isnt y.length
    ret = false
  else
    check = 0
    for i in [0...x.length]
      check += (x.readUInt8(i) ^ y.readUInt8(i))
    ret = (check is 0)
  ret

#=========================================================
