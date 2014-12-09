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
      when K.packet_tags.p3skb
        {P3SKB} = require './p3skb'
        P3SKB.alloc {tag, body }
      else
        [ (new Error "unknown packet tag: #{tag}"), null ]

#==================================================================================================

exports.Packet = Packet

#==================================================================================================

