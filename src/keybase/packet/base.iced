util = require '../../util'
{seal} = require '../encode'
K = require('../../const').kb

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->

  #----------------------

  frame_packet : () -> { tag : @tag(), body : @get_packet_body() }

  #----------------------

  frame_packet_armored : ({dohash}) ->
    obj = @frame_packet()
    seal({ obj, dohash }).toString('base64')

  #----------------------

  is_signature : () -> false
  is_p3skb : () -> false

  #----------------------

  @alloc : ({tag, body}) ->
    ret = err = null
    ret = switch tag
      when K.packet_tags.p3skb
        {P3SKB} = require './p3skb'
        P3SKB.alloc {tag, body }
      when K.packet_tags.signature
        {Signature} = require './signature'
        Signature.alloc { tag, body }
      else
        err = new Error "unknown packet tag: #{tag}"
        null
    [err, ret]

  #----------------------

  unbox : (params, cb) ->
    cb new Error "unbox() unimplemented for tag=#{@tag}"

#==================================================================================================

exports.Packet = Packet

#==================================================================================================

