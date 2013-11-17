util = require '../util'
C = require('../../const').openpgp
packetsigs = require './packetsigs'

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->
    @_psc = new packetsigs.Collection()

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

  push_sig : (packetsig) ->
    @_psc.push packetsig

#==================================================================================================


exports.Packet = Packet

#==================================================================================================
