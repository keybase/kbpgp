util = require '../util'
{pack} = require 'purepack'
K = require('../const').kb

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->
  frame_packet : (tag, body) -> pack { tag, body }, 'buffer', { byte_arrays : true }
   
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

