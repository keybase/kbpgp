
{make_esc} = require 'iced-error'
{burn} = require './burner'
processor = require './processor'
{decode} = require './armor'
C = require '../const'
{SignatureEngineInterface} = require '../kmi'

#=================================================================

exports.decode_sig = decode_sig = ({armored}) ->
  [ err, msg ] = decode armored
  mt = C.openpgp.message_types
  if not err? and (msg.type isnt mt.generic)
    err = new Error "wrong message type; expected a generic message; got #{msg.type}"
  return [ err, msg ]

exports.get_sig_body = get_sig_body = ({armored}) ->
  res = null
  [ err, msg ] = decode_sig {armored}
  res = msg.body unless err?
  return [ err, res ]

#=================================================================

exports.SignatureEngine = class SignatureEngine extends SignatureEngineInterface

  #-----

  constructor : ({@km}) ->
  get_km      : -> @km

  #-----

  box         : (msg, cb) ->
    out = { type : "pgp" }
    if (signing_key = @km.find_signing_pgp_key())?
      await burn { msg, signing_key }, defer err, out.pgp, out.raw
      out.armored = out.pgp unless err?
    else err = new Error "No signing key found"
    cb err, out

  #-----

  get_unverified_payload_from_raw_sig_body : ({body}, cb) ->
    esc = make_esc cb, "get_payload_from_raw_sig_body"
    payload = null
    m = new processor.Message {}
    await m.parse_and_inflate body, esc defer literals
    if (n = literals.length) isnt 1 or not (l = literals[0])?
      err = new Error "Got #{n} literals; only wanted 1"
    else
      payload = l.data
    cb err, payload

  #-----

  get_body : (args, cb) ->
    [ err, res ] = get_sig_body(args)
    cb err, res

  #-----

  decode : (armored, cb) ->
    [ err, msg ] = decode_sig {armored}
    cb err, msg

  #-----

  unbox : (msg, cb, opts = {}) ->
    esc = make_esc cb, "SignatureEngine::unbox"
    if typeof(msg) is 'string'
      await @decode msg, esc defer msg
    opts.keyfetch = @km
    opts.strict = true
    eng = new processor.Message opts
    await eng.parse_and_process { body : msg.body }, esc defer literals
    await @_check_result literals, esc defer payload
    cb null, payload, msg.body

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
