
{burn} = require './burner'
processor = require './processor'

#-----------------------------

exports.SignatureEngine = class SignatureEngine

  #-----

  constructor : ({@km}) ->
  get_km      : -> @km

  #-----

  box         : (msg, cb) ->
    out = {}
    if (signing_key = @km.find_signing_pgp_key())?
      await burn { msg, signing_key }, defer err, out.pgp, out.raw
    else err = new Error "No signing key found"
    cb err, out

  #-----

  unbox       : (msg, cb) ->
    eng = new processor.Message { keyfetch : @km }
    eng.parse_and_process { body : msg.body }, cb

#-----------------------------

exports.box = burn
exports.unbox = processor.do_message

#-----------------------------

