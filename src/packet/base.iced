util = require '../util'
C = require('../const').openpgp

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->

  #----------------------
   
  frame_packet : (tag, body) ->
    bufs = [
      new Buffer([ (0xc0 | tag) ]),
      util.encode_length(body.length),
      body
    ]
    Buffer.concat bufs

  #----------------------

  set_lengths : (real_packet_len, header_len) ->
    @real_packet_len = real_packet_len
    @header_len = header_len

  #----------------------

  set_tag : (t) -> @tag = t

  #----------------------

  is_signature : () -> false

  #----------------------

  is_key_material : () -> false

#==================================================================================================


exports.Packet = Packet

#==================================================================================================
