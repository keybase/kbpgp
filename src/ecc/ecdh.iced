bn = require '../bn'
{xxd,uint_to_buffer,bufeq_secure,ASP} = require '../util'
{make_esc} = require 'iced-error'
konst = require '../const'
C = konst.openpgp
{BaseKeyPair,BaseKey} = require '../basekeypair'
{SRF,MRF} = require '../rand'
{eme_pkcs1_encode,eme_pkcs1_decode} = require '../pad'
{BaseKeyPair} = require '../basekeypair'
{BaseEccKey} = require './base'
hashmod = require '../hash'
sym = require '../symmetric'
{SlicerBuffer} = require '../openpgp/buffer'
{unwrap} = require '../rfc3394'

#=================================================================

class Pub extends BaseEccKey

  @type : C.public_key_algorithms.ECDH
  type : Pub.type

  #----------------

  read_params : (sb) ->
    if (size = sb.read_uint8()) < (n = C.ecdh.param_bytes)
      throw new Error "Need at least #{n} bytes of params; got #{size}"
    if (val = sb.read_uint8()) isnt (v = C.ecdh.version)
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
      uint_to_buffer(8,C.ecdh.param_bytes),
      uint_to_buffer(8,C.ecdh.version),
      uint_to_buffer(8,@hasher.type),
      uint_to_buffer(8,@cipher.type)
    ]
  #----------------
  
  serialize : () -> Buffer.concat [ super(), @serialize_params() ]

  #----------------

  encrypt : (m, cb) ->
    await SRF().random_zn @p.subtract(bn.nbv(2)), defer k
    k = k.add(bn.BigInteger.ONE)
    c = [
      @g.modPow(k, @p),
      @y.modPow(k, @p).multiply(m).mod(@p)
    ]
    cb c

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

  format_params : ({fingerprint}) ->
    Buffer.concat [
      uint_to_buffer(8, @pub.curve.oid.length),
      @pub.curve.oid,
      uint_to_buffer(8, @pub.type),
      @pub.serialize_params(),
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
    o_bytes = @pub.cipher.key_size 

    # Write S = (x,y) and only output x to buffer
    # This is the "compact" representation of S, since y
    # is implied by x.
    X_compact = @pub.curve.point_to_mpi_buffer_compact X
    buf = Buffer.concat [
      (new Buffer [0,0,0,1]),
      X_compact,
      params
    ]
    hash = @pub.hasher buf

    # Only need o_bytes worth of hashed material
    return hash[0...o_bytes]

  #----------------

  decrypt : (c, { fingerprint}, cb) ->
    esc = make_esc cb, "Priv::decrypt"
    {curve} = @pub

    await c.load_V curve, esc defer V

    # S is now the Shared secret point
    S = V.multiply @x

    params = @format_params { fingerprint }

    key = @kdf { X : S, params }

    [err, ret] = unwrap { key, ciphertext : c.C_buf , cipher : @pub.cipher }
    
    cb err, ret 

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : C.public_key_algorithms.ECDH
  type : Pair.type

  #--------------------
  
  # ElGamal keys are always game for encryption
  fulfills_flags : (flags) -> 
    good_for = (C.key_flags.encrypt_comm | C.key_flags.encrypt_storage)
    ((flags & good_for) is flags)

  #--------------------
  
  can_sign : () -> false
  @parse : (pub_raw) -> 
    ret = BaseKeyPair.parse Pair, pub_raw
    return ret

  #----------------
  
  max_value : () -> @pub.p

  #----------------
  
  pad_and_encrypt : (data, cb) ->
    err = ret = null
    await eme_pkcs1_encode data, @pub.p.mpi_byte_length(), defer err, m
    unless err?
      await @pub.encrypt m, defer c_mpis
      ret = @export_output { c_mpis }
    cb err, ret

  #----------------

  decrypt_and_unpad : (ciphertext, {fingerprint}, cb) ->
    err = ret = null
    await @priv.decrypt ciphertext, { fingerprint }, defer err, m
    console.log "shit!"
    console.log err
    console.log m
    unless err?
      b = m.to_padded_octets @pub.p
      [err, ret] = eme_pkcs1_decode b
    cb err, ret

  #----------------

  @parse_output : (buf) -> (Output.parse buf)
  export_output : (args) -> new Output args

#=================================================================

class Output

  #----------------------

  constructor : ({@V_buf, @C_buf}) ->

  #----------------------

  load_V : (curve, cb) -> 
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
    C_buf = sb.consume_rest_to_buffer()
    if (a = C_buf.length) isnt n_bytes
      throw new Error "bad C input: wanted #{n_bytes} bytes, but got #{a}"

    # More decoding of encryption output to follow....
    ret = new Output { V_buf, C_buf }
    return ret

  #----------------------

  hide : ({key, max, slosh}, cb) ->
    cb new Error "not implemented for ECDH!"

  #----------------------

  find : ({key}) ->
    throw new Error "not implemented for ECDH!"

  #----------------------
  
  get_c_bufs : () ->
    if @c_bufs? then @c_bufs
    else (@c_bufs = (i.to_mpi_buffer() for i in @c_mpis))

  #----------------------
  
  output : () -> Buffer.concat @get_c_bufs()

#=======================================================================

exports.ECDH = exports.Pair = Pair

#=================================================================

