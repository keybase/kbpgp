util = require '../util'
C = require('../../const').openpgp
packetsigs = require './packetsigs'
stream = require 'stream'

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->
    @_psc = new packetsigs.Collection()

  #----------------------

  tagbuf : (tag) ->
    tag or= @TAG
    new Buffer [ (0xc0 | tag) ]

  #----------------------

  frame_packet : (tag, body) ->
    bufs = [
      @tagbuf(tag),
      util.encode_length(body.length),
      body
    ]
    Buffer.concat bufs

  #----------------------

  write : (cb) ->
    err = ret = null
    await @write_unframed defer err, raw
    ret = @frame_packet @TAG, raw unless err?
    cb err, ret

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

  #----------------------

  set_xbt_root_metadata : (xbt, cb) -> cb null

#==================================================================================================

exports.Packet = Packet

#==================================================================================================
