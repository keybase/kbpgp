bn = require './bn'
{nbv,nbi,BigInteger} = bn
{bufeq_secure,ASP} = require './util'
{make_esc} = require 'iced-error'
konst = require './const'
C = konst.openpgp
K = konst.kb
{SHA512} = require './hash'
{eme_pkcs1_encode,eme_pkcs1_decode,emsa_pkcs1_decode,emsa_pkcs1_encode} = require './pad'
{SRF,MRF} = require './rand'

#=================================================================

class Pub

  @type : C.public_key_algorithms.RSA
  type : Pub.type

  #----------------

  constructor : ({@p, @q, @g, @y}) ->

  #----------------

  verify : ([r,s], cb) ->

  #----------------

  serialize : () -> 
    Buffer.concat [
      @n.to_mpi_buffer()
      @e.to_mpi_buffer() 
    ]

  #----------------

  @alloc : (raw) ->
    orig_len = raw.length
    order = [ 'p', 'q', 'g', 'y' ]
    d = {}
    err = null
    for o in order when not err?
      [err, d.o, raw ] = bn.mpi_from_buffer raw
    if err then [ err, null ]
    else [ null, new Pub(d), (orig_len - raw.length) ]

#=================================================================

class Pair

  @parse : (pub_raw) -> 
    [err, key, len] = Pub.alloc pub_raw
    key = new Pair { pub : key } if key?
    [err, key, len ]

  #----------------

  verify_unpad_and_check_hash : (sig, data, hasher, cb) ->
    err = null
    [err, sig] = Pair.read_sig_from_buf(sig) if Buffer.isBuffer(sig)
    hash = hasher data
    await @verify sig, defer v

  #----------------

  # Parse a signature out of a packet
  #
  # @param {SlicerBuffer} slice The input slice
  # @return {BigInteger} the Signature
  # @throw {Error} an Error if there was an overrun of the packet.
  @parse_sig : (slice) -> 
    buf = slice.peek_rest_to_buffer()
    [err, ret, n] = @read_sig_from_buf buf
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

#=================================================================

exports.DSA = exports.Pair = Pair

#=================================================================

