{sign} = require 'tweetnacl'
{SRF} = require '../rand'
konst = require '../const'
K = konst.kb
{bufeq_fast} = require '../util'

TYPE = K.kid.public_key_algorithms.NACL_EDDSA

#=============================================

class Pub

  @HEADER : new Buffer([K.kid.version, TYPE ])
  @TRAILER : new Buffer([K.kid.trailer])
  @LEN : Pub.HEADER.length + Pub.TRAILER.length + sign.publicKeyLength

  constructor : (@key) ->

  ekid : () -> Buffer.concat [Pub.HEADER, @key, Pub.TRAILER ]

  @alloc : (kid) ->
    err = key = null
    err = if kid.length isnt Pub.LEN then new Error "bad key length"
    else if not bufeq_fast(kid[-1:], Pub.TRAILER) then new Error "bad trailing byte"
    else if not bufeq_fast(kid[0:2], Pub.HEADER) then new Error "bad header"
    else
      key = new Pub kid[2:-1]
      null
    return [ err, key ]

#=============================================

class Priv

  constructor : (@key) ->

  alloc : (raw) ->
    err = key = null
    if raw.length isnt sign.secretKeyLength
      err = new Error "Bad secret key length"
    else
      key = new Priv raw
    return [err, key]

#=============================================

class Pair

  constructor : ({@pub, @priv}) ->

  @generate : (params, cb) ->
    await SRF.random_bytes sign.seedLength, defer seed
    {secretKey, publicKey} = sign.keyPair.fromSeed(seed)
    pub = new Pub publicKey
    priv = new Priv secretKey
    cb null, new Pair {pub, priv}

  can_sign : () -> @priv?
  can_decrypt : () -> false
  type : () -> TYPE

  good_for_flags : () -> C.key_flags.sign_data | C.key_flags.certify_keys | C.key_flags.auth

  fulfills_flags : (flags) ->
    mask = @good_for_flags()
    return (flags & mask) is mask

  @alloc : (packet) ->
    err = priv = pub = ret = null
    if packet.has_private()
      if packet.is_locked()
        err = new Error "key is still locked"
      else
        [err, priv] = Priv.alloc packet.get_private_data()
    if not err?
      [err, pub] = Pub.alloc packet.get_public_data()
    unless err?
      ret = new Pair { pub, priv }
    return [ err, ret]

  ekid : () -> @pub.ekid()

#=============================================

exports.EdDSA = exports.Pair = Pair

#=============================================

