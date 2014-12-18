{sign} = require 'tweetnacl/nacl-fast'
{SRF} = require '../rand'
konst = require '../const'
K = konst.kb
{genseed,bufeq_secure,bufeq_fast} = require '../util'
{BaseKey,BaseKeyPair} = require '../basekeypair'
NaclDh = require('./dh').Pair

TYPE = K.public_key_algorithms.NACL_EDDSA
exports.b2u = b2u = (b) -> new Uint8Array(b)
exports.u2b = u2b = (u) -> new Buffer u

#=============================================

class Pub

  #--------------------


  @HEADER : new Buffer([K.kid.version, TYPE ])
  @TRAILER : new Buffer([K.kid.trailer])
  @LEN : Pub.HEADER.length + Pub.TRAILER.length + sign.publicKeyLength

  #--------------------

  constructor : (@key) ->

  #--------------------

  @alloc_kb : (kid) ->
    err = key = null
    err = if kid.length isnt Pub.LEN then new Error "bad key length"
    else if not bufeq_fast(kid[-1...], Pub.TRAILER) then new Error "bad trailing byte"
    else if not bufeq_fast(kid[0...2], Pub.HEADER) then new Error "bad header"
    else
      key = new Pub kid[2...-1]
      null
    return [ err, key ]

  #--------------------

  serialize : () -> @key
  nbits : -> 255
  read_params : (sb) ->

  #--------------------

  # Verify a signature with the given payload.
  verify : ({payload,sig,detached}, cb) ->

    if detached
      payload = new Buffer [] if not payload?
      if not sign.detached.verify b2u(payload), b2u(sig), b2u(@key)
        err = new Error "signature didn't verify"
    else if not (r_payload = sign.open b2u(sig), b2u(@key))?
      err = new Error "signature didn't verify"
    else if not (r_payload = u2b r_payload)?
      err = new Error "failed to convert from a Uint8Array to a buffer"
    else if payload? and not bufeq_secure(r_payload, payload)
      err = new Error "got unexpected payload"
    else
      payload = r_payload

    cb err, payload

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
    f = if detached then sign.detached else sign
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

  @type : K.public_key_algorithms.NACL_EDDSA
  type : Pair.type
  get_type : () -> @type
  @klass_name : "EDDSA"

  #--------------------

  constructor : ({ pub, priv }) -> super { pub, priv }
  can_encrypt : () -> false
  hash : () -> @serialize()

  #----------------

  sign_kb : ({payload, detached}, cb) ->
    err = sig = null
    if @priv?
      await @priv.sign { payload, detached}, defer sig
    else
      err = new Error "no secret key available"
    cb err, sig

  #----------------

  verify_kb : ({payload, sig, detached}, cb) ->
    @pub.verify {payload, sig, detached}, cb

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

  @parse_kb : (pub_raw) -> BaseKeyPair.parse_kb Pair, pub_raw

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

  @generate : ({seed, split, server_half}, cb) ->
    arg = { seed, split, len : sign.seedLength, server_half }
    await genseed arg, defer err, { server_half, seed }

    unless err?
      {secretKey, publicKey} = sign.keyPair.fromSeed(b2u(seed))

      # Note that the tweetnacl library deals with Uint8Arrays,
      # and internally, we like node-style Buffers.
      pub = new Pub u2b publicKey
      priv = new Priv u2b secretKey

    cb err, (new Pair {pub, priv}), server_half

#=============================================

exports.EdDSA = exports.Pair = Pair

#=============================================

