konst = require './const'
C = konst.openpgp
K = konst.kb
{SHA256,SHA512} = require './hash'
bn = require './bn'
{bufeq_secure} = require('pgp-utils').util
{SRF} = require './rand'

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

  validity_check : (cb) -> cb null

#============================================================

exports.BaseKeyPair = class BaseKeyPair

  #----------------

  constructor : ({@priv, @pub}) ->
    @pub.parent = @
    @priv.parent = @ if @priv?

  #----------------

  serialize : () -> @pub.serialize()
  hash : () -> SHA256 @serialize()
  ekid : () ->  Buffer.concat [
    new Buffer([K.kid.version, @get_type()]),
    @hash(),
    new Buffer([K.kid.trailer])
  ]
  can_sign : () -> @priv?
  can_decrypt : () -> @priv?
  has_private : () -> @priv?
  fulfills_flags : (flags) -> false
  is_toxic : () -> false
  nbits : () -> @pub?.nbits()
  good_for_flags : () -> (C.key_flags.encrypt_comm | C.key_flags.encrypt_storage | C.key_flags.certify_keys | C.key_flags.sign_data)

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

  # There might be a simplified Keybase format for this key.
  @parse_kb : (klass, pub_raw) ->
    [err, key, len ] = klass.Pub.alloc_kb pub_raw
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

  # Undoing the find operation is quite easy....
  find : (i) -> i.mod(@max_value())

  #----------------

  # Hide bigint i as a bigint of max+slosh bits, that's still
  # equivalent to i mod n.
  hide : ({i, max, slosh}, cb) ->

    ret = err = null

    # For RSA, this is n; for ElGamal and DSA, this is p
    n = @max_value()

    if (L = n.bitLength()) > max
      err = new Error "Can't hide > #{max} bits; got #{L}"
    else
      r_bits = (max - L) + slosh
      await SRF().random_nbit r_bits, defer r
      ret = r.multiply(n).add(i)

    cb err, ret

  #----------------

  validity_check : (cb) -> @pub.validity_check cb

  #----------------

  _dsa_verify_update_and_check_hash : ({ sig, data, hasher, hash, klass}, cb) ->
    err = null

    # It's a little bit of a hack that we have a buffer on a raw unparsed
    # value, but it turns out to be true for DSA, ECDSA and EdDSA
    [err, sig] = klass.read_sig_from_buf(sig) if Buffer.isBuffer(sig)
    hash or= hasher data
    if sig.length isnt 2
      err = new Error "Need an [r,s] pair for a DSA-style signature"
    else
      await @pub.verify sig, hash, defer err, v
    cb err

  #----------------

#============================================================
