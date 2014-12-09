{uint_to_buffer,bufeq_secure,ASP} = require '../util'
{make_esc} = require 'iced-error'
konst = require '../const'
Const = konst.openpgp
{BaseKeyPair,BaseKey} = require '../basekeypair'
{ecc_pkcs5_pad_data} = require '../pad'
{generate,BaseEccKey} = require './base'
hashmod = require '../hash'
sym = require '../symmetric'
{SlicerBuffer} = require '../openpgp/buffer'
{wrap,unwrap} = require '../rfc3394'

#=================================================================

class Pub extends BaseEccKey

  @type : Const.public_key_algorithms.ECDH
  type : Pub.type

  #----------------

  apply_defaults : () ->
    @cipher or= sym.get_cipher()
    @hasher or= hashmod.SHA512

  #----------------

  read_params : (sb) ->
    if (size = sb.read_uint8()) < (n = Const.ecdh.param_bytes)
      throw new Error "Need at least #{n} bytes of params; got #{size}"
    if (val = sb.read_uint8()) isnt (v = Const.ecdh.version)
      throw new Error "Cannot deal with future extensions, byte=#{val}; wanted #{v}"

    # Will throw if either hasher or cipher cannot be found
    @hasher = hashmod.alloc_or_throw sb.read_uint8()
    @cipher = sym.get_cipher sb.read_uint8()

    # 1 byte for each of the three above fields
    sb.advance(size - 3)

  #----------------

  @alloc : (raw) -> BaseEccKey.alloc Pub, raw

  #----------------

  serialize_params : () ->
    Buffer.concat [
      uint_to_buffer(8,Const.ecdh.param_bytes),
      uint_to_buffer(8,Const.ecdh.version),
      uint_to_buffer(8,@hasher.type),
      uint_to_buffer(8,@cipher.type)
    ]
  #----------------

  serialize : () -> Buffer.concat [ super(), @serialize_params() ]

  #----------------

  format_params : ({fingerprint}) ->
    Buffer.concat [
      uint_to_buffer(8, @curve.oid.length),
      @curve.oid,
      uint_to_buffer(8, @type),
      @serialize_params(),
      (new Buffer "Anonymous Sender    ", "utf8"),
      fingerprint
    ]

  #----------------

  #
  # See RFC6637 Section 7
  #  http://tools.ietf.org/html/rfc6637#section-7
  #
  # o_bits is the size of the AES being used (via KeyWrap stuff).
  # No reason to pass it in
  kdf : ({X,params}) ->
    o_bytes = @cipher.key_size

    # Write S = (x,y) and only output x to buffer
    # This is the "compact" representation of S, since y
    # is implied by x.
    X_compact = @curve.point_to_mpi_buffer_compact X
    buf = Buffer.concat [
      (new Buffer [0,0,0,1]),
      X_compact,
      params
    ]
    hash = @hasher buf

    # Only need o_bytes worth of hashed material
    return hash[0...o_bytes]

  #----------------

  encrypt : (m, {fingerprint}, cb) ->
    {n,G} = @curve

    # Pick a random v in Z_n
    await @curve.random_scalar defer v
    V = G.multiply v

    # S is the shared point.  If we send V, the private key holder can
    # compute S = rV = rvG = vrG = vR
    S = @R.multiply v

    params = @format_params { fingerprint }
    key = @kdf { X : S, params }

    # Now wrap the plaintext m (which is really an AES key)
    # with the shared key `key`
    C = wrap { key, plaintext : m, @cipher }

    cb {V,C}

#=================================================================

class Priv extends BaseKey

  #----------------

  # The serialization order of the parameters in the public key
  @ORDER : [ 'x' ]
  ORDER : Priv.ORDER

  #-------------------

  constructor : ({@x,@pub}) ->

  #-------------------

  serialize : () -> @x.to_mpi_buffer()
  @alloc : (raw, pub) -> BaseKey.alloc Priv, raw, { pub }

  #----------------

  decrypt : (c, { fingerprint}, cb) ->
    esc = make_esc cb, "Priv::decrypt"
    {curve} = @pub

    await c.load_V curve, esc defer V

    # S is now the Shared secret point
    S = V.multiply @x

    params = @pub.format_params { fingerprint }

    key = @pub.kdf { X : S, params }

    [err, ret] = unwrap { key, ciphertext : c.C , cipher : @pub.cipher }

    cb err, ret

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : Const.public_key_algorithms.ECDH
  type : Pair.type
  @klass_name : "ECDH"
  get_type : () -> @type

  #--------------------

  # ElGamal keys are always game for encryption
  fulfills_flags : (flags) ->
    good_for = (Const.key_flags.encrypt_comm | Const.key_flags.encrypt_storage)
    ((flags & good_for) is flags)

  #--------------------

  can_sign : () -> false
  @parse : (pub_raw) ->
    ret = BaseKeyPair.parse Pair, pub_raw
    return ret

  #----------------

  max_value : () -> @pub.p

  #----------------

  pad_and_encrypt : (data, {fingerprint}, cb) ->
    err = ret = null
    [err, m] = ecc_pkcs5_pad_data data
    unless err?
      await @pub.encrypt m, {fingerprint}, defer {C,V}
      ret = @export_output { C, V, curve : @pub.curve }
    cb err, ret

  #----------------

  decrypt_and_unpad : (ciphertext, {fingerprint}, cb) ->
    err = ret = null
    await @priv.decrypt ciphertext, { fingerprint }, defer err, m
    cb err, m, true

  #----------------

  @parse_output : (buf) -> (Output.parse buf)
  export_output : (args) -> new Output args

  #----------------------

  @generate : ({nbits, asp}, cb) ->
    await generate { nbits, asp, Pair }, defer err, pair
    unless err?
      # Make sure we have algorithms for hasher and cipher
      pair.pub.apply_defaults()
    cb err, pair

#=================================================================

class Output

  #----------------------

  constructor : ({@V_buf, @C, @V, @curve}) ->

  #----------------------

  load_V : (curve, cb) ->
    @curve = curve
    [err, @V] = curve.mpi_point_from_buffer @V_buf
    cb err, @V

  #----------------------

  @parse : (buf) ->

    # read the shared point S as a raw buffer, since we don't
    # want to decode it until we've allocated the curve.
    sb = new SlicerBuffer buf
    n_bits = sb.read_uint16()
    n_bytes = Math.ceil( n_bits / 8 )
    V_buf = Buffer.concat [ buf[0...2], sb.read_buffer(n_bytes) ]
    n_bytes = sb.read_uint8()

    # C is the encrypted shared key, which we also read in as a buffer
    C = sb.consume_rest_to_buffer()
    if (a = C.length) isnt n_bytes
      throw new Error "bad C input: wanted #{n_bytes} bytes, but got #{a}"

    # More decoding of encryption output to follow....
    ret = new Output { V_buf, C }
    return ret

  #----------------------

  get_V_buf : () ->
    @V_buf = @curve.point_to_mpi_buffer @V unless @V_buf?
    @V_buf

  #----------------------

  hide : ({key, max, slosh}, cb) -> cb null

  #----------------------

  find : ({key}) ->  # noop

  #----------------------

  good_for_flags : () -> (C.key_flags.encrypt_comm | C.key_flags.encrypt_storage)

  #----------------------

  output : () ->
    Buffer.concat [
      @get_V_buf(),
      uint_to_buffer(8, @C.length),
      @C
    ]


#=======================================================================

exports.ECDH = exports.Pair = Pair

#=================================================================

