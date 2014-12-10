
{make_esc} = require 'iced-error'
{burn} = require './burner'
processor = require './processor'

#=================================================================

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
    esc = make_esc cb, "SignatureEngine::unbox"
    eng = new processor.Message { keyfetch : @km }
    await eng.parse_and_process { body : msg.body }, esc defer literals
    await @_check_result literals, esc defer payload
    cb null, payload

  #-----

  _check_result : (literals, cb) ->
    err = payload = null
    if (n = literals.length) isnt 1 or not (l = literals[0])?
      err = new Error "Expected only one pgp literal; got #{n}"
    else if not (sw = l.get_data_signer()?.sig)?
      err = new Error "Expected a signature on the payload message"
    else if not (@km.find_pgp_key (b = sw.get_key_id()))?
      err = new Error "Failed sanity check; didn't have a key for '#{b.toString('hex')}'"
    else
      payload = l.data
    cb err, payload

#=================================================================
