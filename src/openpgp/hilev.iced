
{burn} = require './burner'
processor = require './processor'

#-----------------------------

class Engine 

  #-----

  constructor : ({@km}) ->
  get_km      : -> @km

  #-----

  unbox       : (msg, cb) -> 
    eng = new processor.Message @km
    eng.parse_and_process { body : msg.body }, cb

  #-----

  _box : ({msg, encryption_key, do_sign}, cb) ->
    out = {}
    signing_key = null
    err = null
    if do_sign and not (signing_key = @km.find_signing_pgp_key())?
      err = new Error "No signing key found"
    unless err?
      await burn { msg, signing_key, encryption_key }, defer err, out.pgp, out.raw
    cb err, out

#-----------------------------

exports.SignatureEngine = class SignatureEngine extends Engine

  #-----

  box : (msg, cb) -> @_box { msg, do_sign : true }, cb

#-----------------------------

exports.EncryptionEngine = class EncryptionEngine extends Engine

  #-------

  box : (d, cb) -> @_box d, cb

#-----------------------------

