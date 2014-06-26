bn = require '../bn'
{nbits,nbv,BigInteger} = bn
{SRF,MRF} = require '../rand'
{bufeq_secure,ASP} = require '../util'
{make_esc} = require 'iced-error'
konst = require '../const'
C = konst.openpgp
K = konst.kb
{BaseKeyPair} = require '../basekeypair'
{SlicerBuffer} = require '../openpgp/buffer'
{alloc_by_oid} = require './curves'

#=================================================================

class Pub

  @type : C.public_key_algorithms.ECDSA
  type : Pub.type

  #----------------

  constructor : ({@curve, @R}) ->

  #----------------

  @_parse : (raw) ->
    sb = new SlicerBuffer raw
    pre = sb.rem()
    l = sb.read_uint8()
    oid = sb.read_buffer(l)
    [err, curve] = alloc_by_oid oid
    throw err if err?
    [err, R] = curve.mpi_point_from_slicer_buffer sb
    throw err if err?
    len = pre - sb.rem()
    pub = new Pub { curve, R}
    return [ pub, len ]

  #----------------

  @parse : (raw) -> 
    pub = len = err = null
    try
      [pub,len] = Pub._parse(raw)
    catch e
      err = e
    return [ err, pub, len ]

  #----------------

  @alloc : (raw) -> Pub.parse(raw)

  #----------------

  nbits : () -> @curve.nbits()

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

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub

  #--------------------

  @type : C.public_key_algorithms.ECDSA
  type : Pair.type

  #--------------------
  
  constructor : ({ pub, priv }) -> super { pub, priv }
  @parse : (pub_raw) -> BaseKeyPair.parse Pair, pub_raw
  can_encrypt : () -> false

  #----------------
  
  # DSA keys are always game for verification
  fulfills_flags : (flags) -> 
    good_for = (C.key_flags.certify_keys | C.key_flags.sign_data)
    ((flags & good_for) is flags)

  #----------------

  verify_unpad_and_check_hash : ({sig, data, hasher, hash}, cb) ->
    err = null
    [err, sig] = Pair.read_sig_from_buf(sig) if Buffer.isBuffer(sig)
    hash or= hasher data
    if sig.length isnt 2
      err = new Error "Expected 2 Bigints in the signature"
    else
      await @pub.verify sig, hash, defer err, v
    cb err

  #----------------

  pad_and_sign : (data, {hasher}, cb) ->
    # XXX use the DSA recommendations for which hash to use
    hasher or= SHA512
    h = hasher data
    await @priv.sign h, defer sig
    cb Buffer.concat(s.to_mpi_buffer() for s in sig)

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

exports.ECDSA = exports.Pair = Pair

#=================================================================

