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
  is_duplicate_primary : () -> false

  #----------------------

  to_userid : () -> null
  to_user_attribute : () -> null
  to_literal : () -> null

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

  push_sig : (packetsig) -> @_psc.push packetsig
  get_psc : () -> @_psc

  #----------------------
  
  get_data_signer  : () -> @get_psc().get_data_signer()
  get_data_signers : () -> @get_psc().get_data_signers()

  #----------------------

  # KeyMaterial packets do something else here, but for everyone
  # else, the answer is nothing doing...
  get_signed_userids : () -> []
  get_subkey_binding : () -> null
  is_self_signed : () -> false

#==================================================================================================

# If we're streaming data and we don't know ahead of time how big it is, 
# we can packetize via this class
class StreamingPacketizer 

  constructor : (@pushfn, log2_chunksz) ->
    log2_chunksz or= 16
    @chunksz = (1 << log2_chunksz)
    @prefix = (0xe0 | log2_chunksz) # AKA 224 + log2_chunksz
    @buffers = []
    @dlen = 0

  push : (buf) ->
    @buffers.push buf
    @dlen += buf.length
    if @dlen >= @chunksz
      buf = Buffer.concat @buffers
      front = buf[0...@chunksz]
      rest = buf[@chunksz...]
      @buffers = [ rest ]
      @dlen = rest.length
      @pushfn Buffer.concat [ (new Buffer [@prefix]), front ]

  flush : () ->
    if @dlen > 0
      buf = Buffer.concat @buffers
      @buffers = []
      @pushfn Buffer.concat [ util.encode_length(@dlen), buf ]
      @dlen = 0

#==================================================================================================

exports.Packet = Packet
exports.StreamingPacketizer = StreamingPacketizer

#==================================================================================================
