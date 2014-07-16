util = require '../util'
C = require('../../const').openpgp
packetsigs = require './packetsigs'
stream = require 'stream'
{PacketizerStream} = require './packetizer_stream'

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

#==================================================================================================

# Useful for Literals, Compressed, and Encrypted packets of Indeterminiate length
#
# The idea is:
#   1. Output the packet tag directly
#   2. Fire up a Packetizer Stream
#   3. Output the header packet to the packetizer
#   4. Output the 

exports.PacketizedOutStream = class PacketizedOutStream extends stream.Transform

  #--------------------------------

  # @param {openpgp.packet.Base} header A header packet to prestream [optional]
  # @param {openpgp.packet.Base} footer A footer packet to add after flush [optional]
  constructor : ({@header}) ->
    @_did_header_stream = false
    @_ps = PacketizerStream.substream @
    super()

  #--------------------------------
  
  _stream_header : (cb) ->
    err = null
    if @header and not @_did_header_stream
      @_did_header_stream = true
      @push @header.tagbuf()
      await @header.write_unframed defer err, hbuf
      if err? then @emit 'error', err
      else await @_ps.write hbuf, defer()
    cb err

  #--------------------------------
  
  _transform : (buf, encoding, cb) ->
    await @_stream_header defer err
    unless err?
      await @_v_transform buf, encoding, defer()
    cb()

  #--------------------------------
  
  _flush : (cb) ->
    await @_stream_header defer err
    unless err?
      await @_v_flush defer()
    cb()

#==================================================================================================

exports.Packet = Packet

#==================================================================================================
