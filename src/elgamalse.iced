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

  @type : C.public_key_algorithms.ELGAMAL_SIGN_AND_ENCRYPT
  type : Pub.type

  @ORDER : []
  ORDER : Pub.ORDER

  #----------------

  constructor : (@raw) ->

  #----------------

  @alloc : (raw) -> 
    BaseKey.alloc Pub, raw

  #----------------

  encrypt : (m, cb) -> cb null

#=================================================================

class Priv extends BaseKey

  #-------------------

  @ORDER : []
  ORDER : Priv.ORDER

  #-------------------

  constructor : (@raw) ->

  #-------------------

  serialize : () -> null
  @alloc : (raw, pub) -> BaseKey.alloc Priv, raw, { pub }

  #----------------

  decrypt : (c, cb) -> cb null

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : C.public_key_algorithms.ELGAMAL_SIGN_AND_ENCRYPT
  type : Pair.type

  #--------------------
  
  fulfills_flags : (flags) -> false
  is_toxic : () -> true

  #--------------------
  
  constructor : ({ pub, priv }) -> super { pub, priv }

  can_sign : () -> false
  can_decrypt : () -> false
  err : () -> new Error "refusing to use ElGamal Sign+Encrypt"

  @parse : (pub_raw) -> 
    ret = BaseKeyPair.parse Pair, pub_raw
    return ret

  #----------------

  pad_and_encrypt : (data, cb) -> cb @err(), null

  #----------------

  decrypt_and_unpad : (ciphertext, params, cb) -> cb @err(), null

  #----------------

  @parse_output : (buf) -> null
  export_output : (args) -> null

#=======================================================================

exports.ElGamalSignEncrypt = exports.Pair = Pair

#=================================================================

