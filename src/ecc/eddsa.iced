kbnacl = require 'keybase-nacl'
{SlicerBuffer} = require '../openpgp/buffer'
{BaseKeyPair,BaseKey} = require '../basekeypair'
util = require '../util'
konst = require '../const'
C = konst.openpgp

#=================================================================
# 
# A PGP wrapper class around EdDSA so that we can use EdDSA PGP
# keys.
#
#=================================================================

class Pub extends BaseKey

  @type : C.public_key_algorithms.EDDSA
  type : Pub.type

  #----------------

  @OID : new Buffer [ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 ]
  OID : Pub.OID
  @MPI_LENGTH_HEADERS : new Buffer [ 0x1, 0x7, 0x40 ]
  MPI_LENGTH_HEADERS : Pub.MPI_LENGTH_HEADERS

  #----------------

  constructor : ({@key}) ->

  #----------------

  nbits : () -> 255

  #----------------

  # No params for ECDSA (as with ECDH)
  read_params : (sb) ->

  #----------------

  trunc_hash : (h) -> bn.bn_from_left_n_bits h, @nbits()

  #----------------

  serialize : () ->
    ret = Buffer.concat [
      (new Buffer [ @OID.length ]),
      @OID,
      @MPI_LENGTH_HEADERS,
      @key
    ]
    ret

  #----------------

  @_alloc : (raw) -> 
    sb = new SlicerBuffer raw
    pre = sb.rem()
    l = sb.read_uint8()
    oid = sb.read_buffer(l)
    expected = Pub.OID
    unless util.bufeq_secure oid, expected
      new Error "Wrong OID in EdDSA key"
    mpi_length_headers = sb.read_buffer Pub.MPI_LENGTH_HEADERS.length
    unless util.bufeq_secure mpi_length_headers, Pub.MPI_LENGTH_HEADERS
      new Error "Wrong MPI length headers"
    key = sb.read_buffer kbnacl.sign.publicKeyLength
    pub = new Pub { key }
    len = pre - sb.rem()
    return [ pub, len ]

  #----------------

  @alloc : (raw) -> 
    pub = len = err = null
    try [ pub, len] = Pub._alloc raw
    catch e then err = e
    return [ err, pub, len ]

  #----------------

  verify : ([r, s], payload, cb) ->
    naclw = kbnacl.alloc { publicKey : @key }
    sig = Buffer.concat [r,s]
    [err, _] = naclw.verify { payload, sig, detached : true }
    cb err

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
    @_dsa_verify_update_and_check_hash { sig, data, hasher, hash, klass : Pair }, cb

  #----------------

  pad_and_sign : (data, {hasher}, cb) ->
    # XXX use the DSA recommendations for which hash to use
    cb new Error "unimplemented"

  #----------------

  # Parse a signature out of a packet
  #
  # @param {SlicerBuffer} slice The input slice
  # @return {Array<buffer,buffer>} the Signature in [r,s] form (as buffers)
  # @throw {Error} an Error if there was an overrun of the packet.
  @parse_sig : (slice) ->
    buf = slice.peek_rest_to_buffer()
    [err, ret, n] = Pair.read_sig_from_buf buf
    throw err if err?
    slice.advance n
    return ret

  #----------------

  @eddsa_value_from_buffer : (buf) ->
    err = ret = null
    vlen = kbnacl.sign.publicKeyLength
    mpi_header_len = 2
    totlen = vlen + mpi_header_len
    if buf.length < totlen
      err = new Error "need #{len} bytes per EdDSA value"
    else if (bits = buf.readUInt16BE(0)) > 0x100 or bits < (0x100 - 40)
      err = new Error "Got an unexpected number of Bits for an EdDSA value: #{bits}"
    else
      ret = buf[2...totlen]
      buf = buf[totlen...]
    return [err, ret, buf]

  #----------------

  #
  # Read the signature out of a buffer
  #
  # @param {Buffer} the buffer to examine
  # @return {Array<Error,Array<buffer,buffer>,n} a triple, consisting
  #  of an error (if one happened); the signature (a tuple of buffers meaning 'r' and 's'),
  #  and finally the number of bytes consumed.
  #
  @read_sig_from_buf : (buf) ->
    orig_len = buf.length
    order = [ 'r', 's' ]
    err = null
    bufs = for o in order when not err?
      [err, x, buf] = Pair.eddsa_value_from_buffer buf
      x
    n = orig_len - buf.length
    ret = if err? then null else bufs
    return [err, ret, n]

  #----------------

  @alloc : (klass, raw) ->
    pub = len = err = null
    try [pub, len] = Pub.alloc raw
    catch e then err = e
    return [err, pub, len]

  #----------------

  good_for_flags : -> (C.key_flags.certify_keys | C.key_flags.sign_data)

  #----------------

  @generate : ({nbits, asp}, cb) ->
    cb new Error "unimplemented"

#=================================================================

exports.EDDSA = exports.Pair = Pair

#=================================================================
