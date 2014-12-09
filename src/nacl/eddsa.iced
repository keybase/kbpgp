{sign} = require 'tweetnacl'
{SRF} = require '../rand'
konst = require '../const'
K = konst.kb
{bufeq_fast} = require '../util'
{BaseKey,BaseKeyPair} = require '../basekeypair'
NaclDh = require('./dh').Pair

TYPE = K.public_key_algorithms.NACL_EDDSA
b2u = (b) -> new Uint8Array(b)
u2b = (u) -> new Buffer u

#=============================================

class Pub

  #--------------------

  @HEADER : new Buffer([K.kid.version, TYPE ])
  @TRAILER : new Buffer([K.kid.trailer])
  @LEN : Pub.HEADER.length + Pub.TRAILER.length + sign.publicKeyLength

  #--------------------

  constructor : (@key) ->

  #--------------------

  @alloc : (kid) ->
    err = key = null
    err = if kid.length isnt Pub.LEN then new Error "bad key length"
    else if not bufeq_fast(kid[-1:], Pub.TRAILER) then new Error "bad trailing byte"
    else if not bufeq_fast(kid[0:2], Pub.HEADER) then new Error "bad header"
    else
      key = new Pub kid[2:-1]
      null
    return [ err, key ]

  #--------------------

  serialize : () -> @key
  hash : () -> @key
  nbits : -> 255
  read_params : (sb) ->

  #--------------------

  # Verify a signature with the given payload.
  verify : ({payload,sig,detached}, cb) ->
    if detached
      payload = new Buffer [] if not payload?
      ok = sign.detached.verify b2u(payload), b2u(sig), b2u(@key)
    else
      ok = sign.verify b2u(sig), b2u(@key)
    err = if ok then null else new Buffer "Signature didn't verify"
    cb err

#=============================================

class Priv

  #--------------------

  constructor : (@key) ->

  #--------------------

  alloc : (raw) ->
    err = key = null
    if raw.length isnt sign.secretKeyLength
      err = new Error "Bad secret key length"
    else
      key = new Priv raw
    return [err, key]

  #--------------------

  sign : ({payload, detached}, cb) ->
    f = if detached? then sign.detached else sign
    sig = u2b(f(b2u(payload), b2u(@key)))
    cb sig

#=============================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : K.public_key_algorithms.EDDSA
  type : Pair.type
  @klass_name : "EDDSA"

  #--------------------

  constructor : ({ pub, priv }) -> super { pub, priv }
  can_encrypt : () -> false

  #----------------

  @subkey_algo : (flags) ->
    if (flags & (C.key_flags.certify_keys | C.key_flags.sign_data)) then Pair
    else NaclDh

  #----------------

  # DSA keys are always game for verification
  fulfills_flags : (flags) ->
    good_for = (C.key_flags.certify_keys | C.key_flags.sign_data)
    ((flags & good_for) is flags)

  #----------------

  verify_unpad_and_check_hash : ({sig, data, hasher, hash}, cb) ->
    cb new Error "verify_unpad_and_check_hash unsupported"

  #----------------

  pad_and_sign : (data, {hasher}, cb) ->
    cb new Error "pad_and_sign unsupported"

  #----------------

  # Parse a signature out of a packet
  #
  # @param {SlicerBuffer} slice The input slice
  # @return {BigInteger} the Signature
  # @throw {Error} an Error if there was an overrun of the packet.
  @parse_sig : (slice) ->
    err = new Error "@parse_sig unsupported"
    throw err

  #----------------

  #
  # Read the signature out of a buffer
  #
  # @param {Buffer} the buffer to examine
  # @return {Array<Error,Array<BigInteger,BigInteger>,n} a triple, consisting
  #  of an error (if one happened); the signature (a tuple of BigIntegers meaning 'r' and 's'),
  #  and finally the number of bytes consumed.
  #
  @read_sig_from_buf : (buf) ->
    err = new Error "@read_sig_from_buf unsupported"
    return [err]

  #--------------------

  @generate : (params, cb) ->
    await SRF.random_bytes sign.seedLength, defer seed
    {secretKey, publicKey} = sign.keyPair.fromSeed(seed)

    # Note that the tweetnacl library deals with Uint8Arrays,
    # and internally, we like node-style Buffers.
    pub = new Pub u2b publicKey
    priv = new Priv u2b secretKey

    cb null, new Pair {pub, priv}

#=============================================

exports.EdDSA = exports.Pair = Pair

#=============================================

