bn = require '../bn'
{nbits,nbv,BigInteger} = bn
{uint_to_buffer,bufeq_secure,ASP} = require '../util'
{make_esc} = require 'iced-error'
konst = require '../const'
C = konst.openpgp
K = konst.kb
{BaseKeyPair,BaseKey} = require '../basekeypair'
{generate,BaseEccKey} = require './base'
{ECDH} = require './ecdh'

#=================================================================

class Pub extends BaseEccKey

  @type : C.public_key_algorithms.ECDSA
  type : Pub.type

  #----------------

  nbits : () -> @curve.nbits()

  #----------------

  # No params for ECDSA (as with ECDH)
  read_params : (sb) ->

  #----------------

  trunc_hash : (h) -> bn.bn_from_left_n_bits h, @nbits()

  #----------------

  @alloc : (raw) -> BaseEccKey.alloc Pub, raw

  #----------------

  verify : ([r, s], h, cb) ->
    err = null
    hi = @trunc_hash(h)

    if ((r.signum() <= 0) or (r.compareTo(@curve.p) > 0))
      err = new Error "bad r"
    else if ((r.signum() <= 0) or (s.compareTo(@curve.p) > 0))
      err = new Error "bad s"
    else

      n = @curve.n
      w = s.modInverse n
      u1 = hi.multiply(w).mod(n)
      u2 = r.multiply(w).mod(n)
      p = @curve.G.multiplyTwo(u1,@R,u2)

      v = p.affineX.mod(n)
      err = new Error "verification failed" unless v.equals(r)
    cb err

#=================================================================

class Priv extends BaseKey

  # The serialization order of the parameters in the private key
  @ORDER : [ 'x' ]
  ORDER : Priv.ORDER

  #-------------------

  constructor : ({@x,@pub}) ->

  #-------------------

  @alloc : (raw, pub) -> BaseKey.alloc Priv, raw, { pub }

  #-------------------

  sign : (h, cb) ->
    err = null
    {n,G} = @pub.curve
    hi = @pub.trunc_hash(h)
    await @pub.curve.random_scalar defer k
    Q = G.multiply(k)
    r = Q.affineX.mod(n)
    throw new Error "invalid r-value" if r.signum() is 0
    s = k.modInverse(n).multiply(hi.add(@x.multiply(r))).mod(n)
    cb [r,s]

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : C.public_key_algorithms.ECDSA
  type : Pair.type
  @klass_name : "ECDSA"
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
    @_dsa_verify_update_and_check_hash { sig, data, hasher, hash, klass : Pair }, cb

  #----------------

  pad_and_sign : (data, {hasher}, cb) ->
    # XXX use the DSA recommendations for which hash to use
    hasher or= SHA512
    h = hasher data
    await @priv.sign h, defer sig
    cb null, Buffer.concat(s.to_mpi_buffer() for s in sig)

  #----------------

  # Parse a signature out of a packet
  #
  # @param {SlicerBuffer} slice The input slice
  # @return {BigInteger} the Signature
  # @throw {Error} an Error if there was an overrun of the packet.
  @parse_sig : (slice) ->
    buf = slice.peek_rest_to_buffer()
    [err, ret, n] = Pair.read_sig_from_buf buf
    throw err if err?
    slice.advance n
    return ret

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
    orig_len = buf.length
    order = [ 'r', 's' ]
    err = null
    ret = for o in order when not err?
      [err, x, buf] = bn.mpi_from_buffer buf
      x
    n = orig_len - buf.length
    return [err, ret, n]

  #----------------

  good_for_flags : -> (C.key_flags.certify_keys | C.key_flags.sign_data)

  #----------------

  @generate : ({nbits, asp}, cb) -> generate { nbits, asp, Pair }, cb

#=================================================================

exports.ECDSA = exports.Pair = Pair

#=================================================================
