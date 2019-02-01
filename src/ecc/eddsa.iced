kbnacl = require 'keybase-nacl'
{SlicerBuffer} = require '../openpgp/buffer'
{uint_to_buffer} = require '../util'
{BaseKeyPair,BaseKey} = require '../basekeypair'
{SRF} = require '../rand'
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

  @OID : Buffer.from [ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 ]
  OID : Pub.OID
  @MPI_LENGTH_HEADERS : Buffer.from [ 0x1, 0x7, 0x40 ]
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
      (Buffer.from [ @OID.length ]),
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
      throw new Error "Wrong OID in EdDSA key"
    mpi_length_headers = sb.read_buffer Pub.MPI_LENGTH_HEADERS.length
    unless util.bufeq_secure mpi_length_headers, Pub.MPI_LENGTH_HEADERS
      throw new Error "Wrong MPI length headers"
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
    # Provided signature might be malformed, remember to fit it to
    # size expected by nacl so it does not throw.
    r = util.fit_to_size kbnacl.sign.signatureLength / 2, r
    s = util.fit_to_size kbnacl.sign.signatureLength / 2, s
    sig = Buffer.concat [r,s]
    [err, _] = naclw.verify { payload, sig, detached : true }
    cb err

#=================================================================

class Priv extends BaseKey

  #-------------------

  constructor : ({@seed, @key, @pub}) ->

  #-------------------

  @_alloc : (raw, pub) ->
    # EDDSA private key is actually a 32-byte seed from which public
    # and secret keys are generated. This way, any random 32-byte
    # number is a valid private key.
    sb = new SlicerBuffer raw
    pre = sb.rem()
    key_len = Math.ceil(sb.read_uint16() / 8)
    if (n = key_len) != (m = kbnacl.sign.seedLength)
      throw new Error "Expected #{m} bytes for EDDSA priv key, got #{n}."

    seed = sb.read_buffer key_len
    { publicKey, secretKey } = kbnacl.alloc({}).genFromSeed { seed }

    unless util.bufeq_secure pub.key, publicKey
      throw new Error 'Loaded EDDSA private key but it does not match the public key.'

    # Along with the secret key, the seed has to be saved, so Priv can
    # be serialized.
    priv = new Priv { seed, key: Buffer.from(secretKey), pub }

    len = pre - sb.rem()
    return [ priv, len ]

  #-------------------

  @alloc : (raw, pub) ->
    priv = len = err = null
    try [priv, len] = Priv._alloc raw, pub
    catch e then err = e
    return [ err, priv, len ]

  #-------------------

  sign : (h, cb) ->
    nacl = kbnacl.alloc({ secretKey: @key })
    ret = nacl.sign { payload: h }
    # nacl.sign returns signature + the message, we want just the
    # signature. gpg keeps the signature as two numbers, r and s, lets
    # keep it that way instead of one 64-byte buffer. We could use
    # {detached} argument to sign here, but it would still return one
    # buffer as one "signature buffer" instead of two, so we might as
    # well split/detach ourselves.
    len = kbnacl.sign.signatureLength/2
    cb [Buffer.from(ret[0...len]), Buffer.from(ret[len...len*2])]

  #-------------------    

  serialize : () ->
    # We can't use base class method, because again, our keys are
    # buffers, not bigints.
    Buffer.concat [ 
      uint_to_buffer(16, kbnacl.sign.seedLength*8),
      @seed
    ]


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
    # TODO: are we really padding this? is this secure?
    # I just copied stuff over from dsa.iced
    hasher or= SHA512
    h = hasher data
    await @priv.sign h, defer sig
    [r, s] = sig
    cb null, Buffer.concat [
      # TODO: Ouch! use some encode_mpi_thing, but which one?
      uint_to_buffer(16, r.length*8),
      r,
      uint_to_buffer(16, s.length*8),
      s
    ]

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
    if (bits = buf.readUInt16BE(0)) > 0x100 or bits < (0x100 - 40)
      err = new Error "Got an unexpected number of Bits for an EdDSA value: #{bits}"
    else
      bytes_len = 2 + Math.ceil(bits/8)
      ret = buf[2...bytes_len]
      buf = buf[bytes_len...]
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
    await SRF().random_bytes kbnacl.sign.seedLength, defer seed
    { publicKey, secretKey } = kbnacl.alloc({}).genFromSeed { seed }
    pub = new Pub { key: Buffer.from(publicKey) }
    priv = new Priv { seed, key: Buffer.from(secretKey), pub }
    ret = new Pair { pub, priv }
    cb null, ret

#=================================================================

exports.EDDSA = exports.Pair = Pair

#=================================================================
