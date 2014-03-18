konst = require './const'
C = konst.openpgp
K = konst.kb
{SHA512} = require './hash'
bn = require './bn'
{bufeq_secure} = require('pgp-utils').util

#============================================================

exports.BaseKey = class BaseKey

  #----------------

  @alloc : (klass, raw, d = {}) ->
    orig_len = raw.length
    err = null
    for o in klass.ORDER when not err?
      [err, d[o], raw ] = bn.mpi_from_buffer raw
    if err then [ err, null ]
    else [ null, new klass(d), (orig_len - raw.length) ]

  #----------------

  serialize : () -> 
    Buffer.concat( @[e].to_mpi_buffer() for e in @ORDER )

  #----------------

#============================================================

exports.BaseKeyPair = class BaseKeyPair

  #----------------

  constructor : ({@priv, @pub}) ->
    @pub.parent = @
    @priv.parent = @ if @priv?

  #----------------

  serialize : () -> @pub.serialize()
  hash : () -> SHA512 @serialize()
  ekid : () ->  Buffer.concat [ new Buffer([K.kid.version, @type]), @hash() ]
  can_sign : () -> @priv?
  can_decrypt : () -> @priv?
  fulfills_flags : (flags) -> false
  is_toxic : () -> false

  #----------------

  eq : (k2) -> (@type is k2.type) and (bufeq_secure @serialize(), k2.serialize())

  #----------------

  # @param {number} ops_mask A Mask of all of the ops requested of this key,
  #    whose individual bits are on kbpgp.const.ops
  #   
  can_perform : (ops_mask) ->
    if (ops_mask & konst.ops.sign) and not @can_sign() then false
    else if (ops_mask & konst.ops.decrypt) and not @can_decrypt() then false
    else true

  #----------------

  @parse : (klass, pub_raw) ->
    [err, key, len ] = klass.Pub.alloc pub_raw
    key = new klass { pub : key } if key?
    [err, key, len]

  #----------------

  add_priv : (priv_raw) ->
    [err, @priv, len] = Priv.alloc priv_raw
    [err, len]

  #----------------

  @alloc : (klass, {pub, priv}) ->
    [err, pub  ] = klass.Pub.alloc  pub
    [err, priv ] = klass.Priv.alloc priv, pub if not err? and priv?
    if err? then [ err, null ]
    else [ null, new klass { priv, pub }]

  #----------------

  read_priv : (raw_priv) ->
    [err,@priv] = @Priv.alloc raw_priv, @pub
    err

  #----------------

#============================================================
