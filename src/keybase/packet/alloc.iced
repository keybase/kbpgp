
K = require('../../const').kb
{P3SKB} = require './p3skb'
{Signature} = require './signature'
{Encryption} = require './encryption'

katch = (f) ->
  try return [null, f()]
  catch e then return [e, null]

exports.alloc = ({tag, body}) ->
  [err, ret] = switch tag
    when K.packet_tags.p3skb
      katch () -> P3SKB.alloc { tag, body }
    when K.packet_tags.signature
      katch () -> Signature.alloc { tag, body }
    when K.packet_tags.encryption
      katch () -> Encryption.alloc { tag, body }
    else
      err = new Error "unknown packet tag: #{tag}"
      [err, null]
  [err, ret]

