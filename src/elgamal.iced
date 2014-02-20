bn = require './bn'
{bufeq_secure,ASP} = require './util'
{make_esc} = require 'iced-error'
konst = require './const'
C = konst.openpgp
K = konst.kb
{BaseKeyPair,BaseKey} = require './basekeypair'
{SRF,MRF} = require './rand'

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

#=================================================================

class Priv extends BaseKey

  #----------------

  # The serialization order of the parameters in the public key
  @ORDER : [ 'x' ]
  ORDER : Pub.ORDER

  #-------------------

  constructor : ({@x,@pub}) ->

  #-------------------

  serialize : () -> @x.to_mpi_buffer()

#=================================================================

class Pair extends BaseKeyPair

  #--------------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #--------------------

  @type : C.public_key_algorithms.ELGAMAL
  type : Pair.type

  #--------------------
  
  constructor : ({ pub, priv }) -> super { pub, priv }
  @parse : (pub_raw) -> BaseKeyPair.parse Pair, pub_raw
  can_sign : () -> false

  #----------------

#=================================================================

exports.ElGamal = exports.Pair = Pair

#=================================================================

