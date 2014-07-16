
main = require '../../'
{keyring,unbox,KeyManager,stream,armor,util} = main
C = main.const
{Faucet,Drain} = require 'iced-stream'

#----------------------------------------------------------------

km = null
short = """
Calmly we walk through this April's day,
Metropolitan poetry here and there,
In the park sit pauper and rentier,
The screaming children, the motor-car
"""
med = "".concat (short for [0...1000])...
userid = "Delmore Schwartz"
keyfetch = null

#----------------------------------------------------------------

exports.generate_ecc_km = (T,cb) ->
  await KeyManager.generate_ecc { userid }, defer err, tmp
  T.no_error err
  km = tmp
  keyfetch = new keyring.PgpKeyRing
  keyfetch.add_key_manager km
  cb()

#----------------------------------------------------------------

sign = ({T,km,plaintext, opts}, cb) ->
  opts or= {}
  await stream.box { sign_with : km, opts}, defer err, xform
  T.no_error err
  buf = new Buffer(plaintext, 'utf8')
  f = new Faucet buf
  d = new Drain()
  f.pipe(xform)
  xform.pipe(d)
  d.once 'finish', () ->
    buf = d.data()
    signed_msg = armor.encode C.openpgp.message_types.generic, buf
    cb signed_msg
  d.once 'error', (err) ->
    T.no_error err
    cb()

#----------------------------------------------------------------

verify = ({T,signed_msg, plaintext, km }, cb) ->
  await unbox { armored : signed_msg, keyfetch }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "signed literal was right"
  T.assert km.is_pgp_same_key(msg[0].get_data_signer().km, km), "the right signing key"
  cb()

#----------------------------------------------------------------

sign_and_verify = (T,plaintext,opts,cb) ->
  arg = { T, km, plaintext, opts }
  await sign arg, defer arg.signed_msg
  T.waypoint "sign"
  await verify arg, defer()
  T.waypoint "verify"
  cb()

#----------------------------------------------------------------

exports.sign_and_verify_shortie = (T,cb) -> sign_and_verify T, short, {}, cb
exports.sign_and_verify_med = (T,cb) -> sign_and_verify T, med, {}, cb

#----------------------------------------------------------------

exports.sign_and_verify_zlib = (T,cb) -> sign_and_verify T, med, { compression : 'zlib' }, cb

#----------------------------------------------------------------
