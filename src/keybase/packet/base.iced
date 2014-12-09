util = require '../../util'
{box} = require '../encode'
K = require('../../const').kb

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->

  #----------------------

  frame_packet : (body) -> { tag : @tag(), body : @get_packet_body() }

  #----------------------

  frame_packet_armored : ({dohash}) ->
    obj = @frame_packet()
    box({ obj, dohash }).toString('base64')

  #----------------------

  is_signature : () -> false
  is_p3skb : () -> false

  #----------------------

  @alloc : (tag, body) ->
    switch tag
      when K.packet_tags.p3skb
        {P3SKB} = require './p3skb'
        P3SKB.alloc {tag, body }
      when K.packet_tags.signature
        {Signature} = require './signature'
        Signature.alloc { tag, body }
      else
        [ (new Error "unknown packet tag: #{tag}"), null ]

  #----------------------

  unbox : (params, cb) ->
    cb new Error "unbox() unimplemented for tag=#{@tag}"

#==================================================================================================

exports.Packet = Packet

#==================================================================================================

