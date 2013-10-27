K = require('../../const').kb
triplesec = require 'triplesec'
{SHA512} = require '../../hash'
{Decryptor} = triplesec
{native_rng} = triplesec.prng
{Packet} = require './base'
{pack,box} = require '../encode'
{make_esc} = require 'iced-error'
rsa = require '../../rsa'
{sign,verify} = require '../sign'
{bufeq_secure,bufferify} = require '../../util'

#=================================================================================

# PGP Triplesec Secret Key Bundle
class P3SKB extends Packet

  constructor : ({@pub,priv_clear}) ->
    super()
    @priv = 
      data : priv_clear
      encryption : K.key_encryption.none

  frame_packet : () ->
    super K.packet_tags.p3skb, { @pub, @priv }

  lock : ({asp, tsenc}, cb) ->
    await tsenc.run { data : @priv.data, progress_hook : asp?.progress_hook }, defer err, ct
    unless err?
      @priv.data = ct
      @priv.encryption = K.key_encryption.triplesec_v2
    cb err

#=================================================================================

