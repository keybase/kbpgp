K = require('../../const').kb
triplesec = require 'triplesec'
{SHA512} = require '../../hash'
{Decryptor} = triplesec
{native_rng} = triplesec.prng
{Packet} = require './base'
{pack,box} = require '../encode'
{make_esc} = require 'iced-error'
rsa = require '../../rsa'
{bufeq_secure,bufferify} = require '../../util'

#=================================================================================

# PGP Triplesec Secret Key Bundle
class P3SKB extends Packet

  @tag : () -> K.packet_tags.p3skb
  tag  : () -> P3SKB.tag()

  constructor : ({@pub,priv_clear,priv, @type}) ->
    super()
    @priv = if priv? then priv
    else if priv_clear? then { data : priv_clear, encryption : K.key_encryption.none }

  get_packet_body : () ->
    ret = { @pub, @priv }
    ret.type = @type if @type?
    ret

  lock : ({asp, tsenc, passphrase_generation}, cb) ->
    await tsenc.run { data : @priv.data, progress_hook : asp?.progress_hook() }, defer err, ct
    unless err?
      @priv.data = ct
      @priv.encryption = K.key_encryption.triplesec_v3
      @priv.passphrase_generation = passphrase_generation if passphrase_generation?
    cb err

  unlock : ({asp, tsenc, passphrase_generation}, cb) ->
    switch @priv.encryption
      when K.key_encryption.triplesec_v3, K.key_encryption.triplesec_v2, K.key_encryption.triplesec_v1
        dec = new Decryptor { enc : tsenc }
        progress_hook = asp?.progress_hook()
        await dec.run { data : @priv.data, progress_hook }, defer err, raw
        dec.scrub()
        if not err?
          @priv.data = raw
          @priv.encryption = K.key_encryption.none
        else if (a = passphrase_generation)? and (b = @priv.passphrase_generation)? and (a isnt b)
          err = new Error "Decryption failed, likely due to old passphrase (wanted v#{a} but got v#{b}) [#{err.toString()}]"
      when K.key_encryption.none then # noop
      else
        err = new Error "Unknown key encryption type: #{k.encryption}"
    cb err

  @alloc : ({tag,body}) ->
    if tag is P3SKB.tag() then new P3SKB body
    else throw new Error "wrong tag found: #{tag}"

  has_private : () -> @priv?
  is_locked : () -> @priv.encryption isnt K.key_encryption.none

  get_private_data : () -> @priv?.data
  get_public_data : () -> @pub
  get_key_type : () -> @type

  is_p3skb : () -> true

#=================================================================================

exports.P3SKB = P3SKB
