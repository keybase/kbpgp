
console.log "+ INC sigeng"
{make_esc} = require 'iced-error'
{box,unbox} = require './box'
console.log require './box'
console.log "- INC sigeng"

#=================================================================

exports.SignatureEngine = class SignatureEngine

  #-----

  constructor : ({@km}) ->
  get_km      : -> @km

  #-----

  box : (msg, cb) ->
    esc = make_esc cb, "SignatureEngine::box"
    await box { msg, sign_with : @km }, esc defer armored
    out = { type : "kb", armored, kb : armored }
    cb null, out

  #-----

  unbox       : (msg, cb) ->
    esc = make_esc cb, "SignatureEngine::unbox"
    err = payload = null
    await unbox { armored : msg }, esc defer res
    if not res.km.eq @km
      a = res.km.get_ekid().toString('hex')
      b = @km.get_ekid().toString('hex')
      err = new Error "Got wrong signing key: #{a} != #{b}"
    else
      payload = res.payload
    cb null, payload

#=================================================================
