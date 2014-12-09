bn = require './bn'
{bufeq_secure,ASP} = require './util'
{make_esc} = require 'iced-error'
konst = require './const'
C = konst.openpgp
K = konst.kb
{BaseKeyPair,BaseKey} = require './basekeypair'
{SRF,MRF} = require './rand'
{eme_pkcs1_encode,eme_pkcs1_decode} = require './pad'

#=================================================================

class Pub extends BaseKey

  @type : C.public_key_algorithms.ELGAMAL
  type : Pub.type

  #----------------

  # The serialization order of the parameters in the public key
  @ORDER : [ 'p', 'g', 'y' ]
  ORDER : Pub.ORDER

  #----------------

  constructor : ({@p, @g, @y}) ->

  #----------------

  @alloc : (raw) ->
    BaseKey.alloc Pub, raw

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

  decrypt : (c, cb) ->
    p = @pub.p
    ret = c[0].modPow(@x,p).modInverse(p).multiply(c[1]).mod(p)
    cb null, ret

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : C.public_key_algorithms.ELGAMAL
  @klass_name : "ELGAMAL"
  type : Pair.type
  get_type : () -> @type

  #--------------------

  # ElGamal keys are always game for encryption
  fulfills_flags : (flags) ->
    good_for = @good_for_flags()
    ((flags & good_for) is flags)

  good_for_flags : () -> (C.key_flags.encrypt_comm | C.key_flags.encrypt_storage)

  #--------------------

  constructor : ({ pub, priv }) -> super { pub, priv }
  can_sign : () -> false
  @parse : (pub_raw) ->
    ret = BaseKeyPair.parse Pair, pub_raw
    return ret

  #----------------

  max_value : () -> @pub.p

  #----------------

  pad_and_encrypt : (data, params, cb) ->
    err = ret = null
    await eme_pkcs1_encode data, @pub.p.mpi_byte_length(), defer err, m
    unless err?
      await @pub.encrypt m, defer c_mpis
      ret = @export_output { c_mpis }
    cb err, ret

  #----------------

  decrypt_and_unpad : (ciphertext, params, cb) ->
    err = ret = null
    await @priv.decrypt ciphertext.c(), defer err, m
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

  constructor : ({@c_mpis, @c_bufs}) ->

  #----------------------

  @parse : (buf) ->
    c_mpis = for i in [0...2]
      [err, ret, buf, n] = bn.mpi_from_buffer buf
      throw err if err?
      ret
    throw new Error "junk at the end of input" unless buf.length is 0
    new Output { c_mpis }

  #----------------------

  c : () -> @c_mpis

  #----------------------

  hide : ({key, max, slosh}, cb) ->
    max or= 4096
    slosh or= 128
    err = null
    @c_bufs = null
    new_c_mpis = []
    for c_mpi in @c_mpis
      await key.hide { i : c_mpi, max, slosh }, defer err, tmp
      new_c_mpis.push tmp
      break if err?
    @c_mpis = new_c_mpis unless err?
    cb err

  #----------------------

  find : ({key}) ->
    @c_mpis = (key.find(j) for j in @c_mpis)

  #----------------------

  get_c_bufs : () ->
    if @c_bufs? then @c_bufs
    else (@c_bufs = (i.to_mpi_buffer() for i in @c_mpis))

  #----------------------

  output : () -> Buffer.concat @get_c_bufs()

#=======================================================================

exports.ElGamal = exports.Pair = Pair

#=================================================================

