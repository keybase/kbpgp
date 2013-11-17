util = require '../util'
C = require('../../const').openpgp

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->
    @signed_by = []

  #----------------------
   
  frame_packet : (tag, body) ->
    bufs = [
      new Buffer([ (0xc0 | tag) ]),
      util.encode_length(body.length),
      body
    ]
    Buffer.concat bufs

  #----------------------

  set : (d) -> (@[k] = v for k,v of d)

  #----------------------

  is_signature : () -> false
  is_key_material : () -> false

  #----------------------

  to_userid : () -> null

  #----------------------

  # ESK = "Encrypted Session Key"
  to_esk_packet : () -> null

  #----------------------

  to_enc_data_packet : () -> null

  #----------------------

  replay : () -> @frame_packet @tag, @raw

  #----------------------

  inflate : (cb) -> cb null, null

  #----------------------

  add_signed_by : (sig) ->
    @signed_by = [] unless @signed_by
    @signed_by.push sig

#==================================================================================================


exports.Packet = Packet

#==================================================================================================
