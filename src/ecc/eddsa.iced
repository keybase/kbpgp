nacl = require 'tweetnacl'
{BaseKeyPair,BaseKey} = require '../basekeypair'
{util} = require '../util'
konst = require '../const'
C = konst.openpgp

#=================================================================

class Pub extends BaseKey

  @type : C.public_key_algorithms.EDDSA
  type : Pub.type

  #----------------

  nbits : () -> 255

  #----------------

  # No params for ECDSA (as with ECDH)
  read_params : (sb) ->

  #----------------

  trunc_hash : (h) -> bn.bn_from_left_n_bits h, @nbits()

  #----------------

  @_alloc : (raw) -> 
    sb = new SlicerBuffer raw
    pre = sb.rem()
    l = sb.read_uint8()
    oid = sb.read_buffer(l)
    expected = new Buffer [ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 ]
    unless util.bufeq_secure oid, expected
      new Error "Wrong OID in EdDSA key"
    cb new Error "not done yet!"

  #----------------

  @alloc : (raw) -> 
    pub = len = err = null
    try [ pub, len] = Priv.alloc raw
    catch e then err = e
    return [ err, pub, len ]

  #----------------

  verify : ([r, s], h, cb) ->
    cb new Error "unimplemented"

#=================================================================

class Priv extends BaseKey

  # The serialization order of the parameters in the private key
  @ORDER : []
  ORDER : Priv.ORDER

  #-------------------

  constructor : ({@x,@pub}) ->

  #-------------------

  @alloc : (raw, pub) ->
    return [ (new Error "unimplemented" ) ]

  #-------------------

  sign : (h, cb) ->
    throw new Error "unimplemented"

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : C.public_key_algorithms.EDDSA
  type : Pair.type
  @klass_name : "EDDSA"
  get_type : () -> @type

  #--------------------

  constructor : ({ pub, priv }) -> super { pub, priv }
  @parse : (pub_raw) -> BaseKeyPair.parse Pair, pub_raw
  can_encrypt : () -> false

  #----------------

  @subkey_algo : (flags) ->
    if (flags & (C.key_flags.certify_keys | C.key_flags.sign_data)) then Pair
    else ECDH

  #----------------

  # DSA keys are always game for verification
  fulfills_flags : (flags) ->
    good_for = (C.key_flags.certify_keys | C.key_flags.sign_data)
    ((flags & good_for) is flags)

  #----------------

  verify_unpad_and_check_hash : ({sig, data, hasher, hash}, cb) ->
    cb new Error "unimplemented"

  #----------------

  pad_and_sign : (data, {hasher}, cb) ->
    # XXX use the DSA recommendations for which hash to use
    cb new Error "unimplemented"

  #----------------

  # Parse a signature out of a packet
  #
  # @param {SlicerBuffer} slice The input slice
  # @return {BigInteger} the Signature
  # @throw {Error} an Error if there was an overrun of the packet.
  @parse_sig : (slice) ->
    throw new Error "unimplemented"

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
    return [ (new Error "unimplemented") ]

  #----------------

  good_for_flags : -> (C.key_flags.certify_keys | C.key_flags.sign_data)

  #----------------

  @generate : ({nbits, asp}, cb) ->
    cb new Error "unimplemented"

#=================================================================

exports.EDDSA = exports.Pair = Pair

#=================================================================
