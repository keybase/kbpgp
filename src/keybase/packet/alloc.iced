
K = require('../../const').kb
{P3SKB} = require './p3skb'
{Signature} = require './signature'
{Encryption} = require './encryption'

katch = (f) ->
  ret = null
  try
    ret = f()
    return [ null, ret]
  catch e
    return [e, null]

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
      null
  [err, ret]

