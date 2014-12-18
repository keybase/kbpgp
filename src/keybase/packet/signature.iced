
konst = require '../../const'
K = konst.kb
C = konst.openpgp
{Packet} = require './base'
{make_esc} = require 'iced-error'
{eddsa} = require '../../nacl/main'

#=================================================================================

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
      new Error "Expected SHA512 (type #{b}); got #{a}"
    else if (a = body.sig_type) isnt (b = Signature.SIG_TYPE)
      err = new Error "Expected EDDSA (type #{b}); got #{a}"
    else
      ret = new Signature body
      null
    throw err if err?
    ret

  #------------------

  is_signature : () -> true

  #------------------

  verify : (cb) ->
    esc = make_esc cb, "verify"
    err = km = null
    [err, pair] = eddsa.Pair.parse_kb @key
    if not err?
      await pair.verify_kb @, esc defer()
    cb err, { keypair : pair, @payload }

  #------------------

  unbox : (params, cb) ->
    await @verify defer err, res
    cb err, res

  #------------------

  @box : ({km, payload}, cb) ->
    esc = make_esc cb, "@sign"
    pair = km.get_keypair()
    detached = true
    await pair.sign_kb { payload, detached }, esc defer sig
    packet = new Signature { key : pair.ekid(), payload, sig, detached }
    cb null, packet

#=================================================================================

exports.Signature = Signature
exports.sign = Signature.sign
