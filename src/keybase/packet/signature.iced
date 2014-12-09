konst = require '../../const'
K = konst.kb
C = konst.openpgp
{Packet} = require './base'
{KeyManager} = require '../keymanager'
{make_esc} = require 'iced-error'

#=================================================================================

# PGP Triplesec Secret Key Bundle
class Signature extends Packet

  @SIG_TYPE : K.public_key_algorithms.NACL_EDDSA
  @HASH_TYPE : C.hash_algorithms.SHA512

  #------------------

  @tag : () -> K.packet_tags.signature
  tag : () -> Signature.tag()

  #------------------

  constructor : ({@key, @payload, @sig, @detached}) ->
    super()

  #------------------

  get_packet_body : () ->
    sig_type = Signature.SIG_TYPE
    hash_type = Signature.HASH_TYPE
    { @key, @payload, @sig, @detached, sig_type, hash_type }

  #------------------

  @alloc : ({tag,body}) ->
    ret = null
    err = if tag isnt Signature.tag() then new Error "wrong tag found: #{tag}"
    else if (a = body.hash_type) isnt (b = Signature.HASH_TYPE)
      new Error "Expeched SHA512 (type #{b}); got #{a}"
    else if (a = packet.sig_type) isnt (b = Signature.SIG_TYPE)
      err = new Error "Expected EDDSA (type #{b}); got #{a}"
    else
      ret = new Signature body
      null
    throw err if err?
    ret

  #------------------

  is_signature : () -> false

  #------------------

  verify : (cb) ->
    err = km = null
    if ([err, pair] = nacl.Pair.parse packet.body.key)? and not err?
      await pair.verify @, esc defer()
      km = new KeyManager { key : pair }
    cb err, { km, @payload }

  #------------------

  unbox : (cb) ->
    await @verify defer err, res
    cb err, res

  #------------------

  @sign : ({km, payload}, cb) ->
    esc = make_esc cb, "@sign"
    pair = km.get_keypair()
    detached = true
    await pair.sign { payload, detached }, esc defer sig
    packet = new Signature { key : pair.ekid(), payload, sig, detached }
    cb null, packet

#=================================================================================

exports.Signature = Signature
exports.sign = Signature.sign
