
K = require('../../const').kb
{P3SKB} = require './p3skb'
{Signature} = require './signature'
{Encryption} = require './encryption'

exports.alloc = ({tag, body}) ->
  ret = err = null
  ret = switch tag
    when K.packet_tags.p3skb
      P3SKB.alloc {tag, body }
    when K.packet_tags.signature
      Signature.alloc { tag, body }
    when K.packet_tags.encryption
      Encryption.alloc { tag, body }
    else
      err = new Error "unknown packet tag: #{tag}"
      null
  [err, ret]

