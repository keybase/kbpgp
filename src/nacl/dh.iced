{box} = require 'tweetnacl'
{SRF} = require '../rand'
konst = require '../const'
K = konst.kb
{genseed,bufeq_fast} = require '../util'
{BaseKey} = require '../basekeypair'
{BaseKeyPair} = require './base'
{b2u,u2b} = require './eddsa'
NaclEddsa = require('./eddsa').Pair

TYPE = K.public_key_algorithms.NACL_DH
b2u = (b) -> new Uint8Array(b)
u2b = (u) -> new Buffer u

#=============================================

class Pub

  #--------------------


  @HEADER : new Buffer([K.kid.version, TYPE ])
  @TRAILER : new Buffer([K.kid.trailer])
  @LEN : Pub.HEADER.length + Pub.TRAILER.length + box.publicKeyLength

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

  encrypt : ({plaintext,sender}, cb) ->
    await SRF().random_bytes box.nonceLength, defer nonce
    res = box b2u(plaintext), b2u(nonce), b2u(@key), b2u(sender.priv.key)
    cb null, {ciphertext : u2b(res), nonce }

#=============================================

class Priv

  constructor : (@key) ->

  #--------------------

  alloc : (raw) ->
    err = key = null
    if raw.length isnt box.secretKeyLength
      err = new Error "Bad secret key length"
    else
      key = new Priv raw
    return [err, key]

  #--------------------

  decrypt : ({ciphertext, nonce, sender}, cb) ->
    err = res = null
    res = box.open b2u(ciphertext), b2u(nonce), b2u(sender.pub.key), b2u(@key)
    if res is false
      err = new Error "decryption failed"
      res = null
    else
      res = u2b res
    cb err, res

#=============================================

class Pair extends BaseKeyPair

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  constructor : ({pub, priv}) -> super { pub, priv }

  #--------------------

  @type : K.public_key_algorithms.NACL_DH
  type : Pair.type
  get_type : () -> @type
  @klass_name : "DH"

  #--------------------

  can_encrypt : () -> true
  can_sign : () -> false
  hash : () -> @serialize()

  #----------------

  encrypt_kb : ({plaintext, sender}, cb) ->
    @pub.encrypt { plaintext, sender}, cb

  #----------------

  decrypt_kb : ({ciphertext, nonce, sender}, cb) ->
    err = plaintex = null
    if @priv?
      await @priv.decrypt { ciphertext, nonce, sender }, defer err, plaintext
    else
      err = new Error "no secret key available"
    cb err, plaintext

  #----------------

  @subkey_algo : (flags) ->
    if (flags & (C.key_flags.encrypt_comm | C.key_flags.encrypt_storage)) then Pair
    else NaclEddsa

  #----------------

  # DSA keys are always game for verification
  fulfills_flags : (flags) ->
    good_for = (C.key_flags.encrypt_comm | C.key_flags.encrypt_storage)
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

  @generate : ({server_half, seed, split}, cb) ->
    arg = { seed, split, len : box.secretKeyLength, server_half }
    await genseed arg, defer err, { server_half, seed }
    ret = null

    unless err?
      {secretKey, publicKey} = box.keyPair.fromSecretKey(b2u(seed))

      # Note that the tweetnacl library deals with Uint8Arrays,
      # and internally, we like node-style Buffers.
      pub = new Pub u2b publicKey
      priv = new Priv u2b secretKey

      ret = new Pair { pub, priv }

    cb err, ret, server_half

#=============================================

exports.DH = exports.Pair = Pair

#=============================================

