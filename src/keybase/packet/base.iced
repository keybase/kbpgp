util = require '../../util'
{pack} = require '../encode'
K = require('../../const').kb

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->

  # XXX don't pack it for now!?!?!
  frame_packet : (tag, body) -> { tag, body }
   
  #----------------------

  @alloc : (tag, body) ->
    switch tag
      when K.packet_tags.secret_key, K.packet_tags.public_key
        {KeyMaterial} = require './keymaterial'
        KeyMaterial.alloc (tag is K.packet_tags.secret_key), body 
      else
        [ (new Error "unknown packet tag: #{tag}"), null ]

#==================================================================================================

exports.Packet = Packet

#==================================================================================================

