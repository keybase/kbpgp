bn = require './bn'
{nbits,nbv,BigInteger} = bn
{SRF,MRF} = require './rand'
{bufeq_secure,ASP} = require './util'
{make_esc} = require 'iced-error'
konst = require './const'
C = konst.openpgp
K = konst.kb
{BaseKey,BaseKeyPair} = require './basekeypair'
{SRF,MRF} = require './rand'

#=================================================================

class Pub extends BaseKey

  @type : C.public_key_algorithms.DSA
  type : Pub.type

  #----------------

  # The serialization order of the parameters in the public key
  @ORDER : [ 'p', 'q', 'g', 'y' ]
  ORDER : Pub.ORDER

  #----------------

  constructor : ({@p, @q, @g, @y}) ->

  #----------------

  @alloc : (raw) -> BaseKey.alloc Pub, raw

  #----------------

  trunc_hash : (h) -> bn.bn_from_left_n_bits h, @q.bitLength()

  #----------------

  nbits : () -> @p?.bitLength()

  #----------------

  verify : ([r, s], h, cb) ->
    err = null
    hi = @trunc_hash(h)
    w = s.modInverse @q
    u1 = hi.multiply(w).mod(@q)
    u2 = r.multiply(w).mod(@q)
    v = @g.modPow(u1, @p).multiply(@y.modPow(u2, @p)).mod(@p).mod(@q)
    err = new Error "verification failed" unless v.equals(r)
    cb err

#=================================================================

class Priv extends BaseKey

  #-------------------

  # The serialization order of the parameters in the public key
  @ORDER : [ 'x' ]
  ORDER : Priv.ORDER

  #-------------------

  constructor : ({@x,@pub}) ->

  #-------------------

  @alloc : (raw, pub) -> BaseKey.alloc Priv, raw, { pub }

  #-------------------

  sign : (h, cb) ->
    err = null
    {p,q,g} = @pub
    hi = @pub.trunc_hash(h)
    await SRF().random_zn q.subtract(bn.nbv(2)), defer k
    k = k.add(bn.BigInteger.ONE)
    r = g.modPow(k,p).mod(q)
    s = (k.modInverse(q).multiply(hi.add(@x.multiply(r)))).mod(q)
    cb [r,s]

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : C.public_key_algorithms.DSA
  type : Pair.type
  get_type : () -> @type
  @klass_name : "DSA"

  #--------------------

  constructor : ({ pub, priv }) -> super { pub, priv }
  @parse : (pub_raw) -> BaseKeyPair.parse Pair, pub_raw
  can_encrypt : () -> false

  #----------------

  # DSA keys are always game for verification
  fulfills_flags : (flags) ->
    good_for = @good_for_flags()
    ((flags & good_for) is flags)

  #----------------

  good_for_flags : -> (C.key_flags.certify_keys | C.key_flags.sign_data)

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

#=================================================================

exports.DSA = exports.Pair = Pair

#=================================================================

