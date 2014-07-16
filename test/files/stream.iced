
main = require '../../'
{keyring,unbox,KeyManager,stream,armor,util} = main
C = main.const
{Faucet,Drain} = require 'iced-stream'

#----------------------------------------------------------------

km = null
plaintext = """
Calmly we walk through this April's day,
Metropolitan poetry here and there,
In the park sit pauper and rentier,
The screaming children, the motor-car
"""
userid = "Delmore Schwartz"
signed_msg = null
keyfetch = null

#----------------------------------------------------------------

exports.generate_ecc_km = (T,cb) ->
  await KeyManager.generate_ecc { userid }, defer err, tmp
  T.no_error err
  km = tmp
  cb()

#----------------------------------------------------------------

exports.sign = (T,cb) ->
  await stream.box { sign_with : km }, defer err, xform
  T.no_error err
  buf = new Buffer(plaintext, 'utf8')
  f = new Faucet buf
  d = new Drain()
  f.pipe(xform)
  xform.pipe(d)
  d.once 'finish', () ->
    buf = d.data()
    signed_msg = armor.encode C.openpgp.message_types.generic, buf
    cb()
  d.once 'error', (err) ->
    T.no_error err
    cb()

#----------------------------------------------------------------

exports.verify = (T,cb) ->
  keyfetch = new keyring.PgpKeyRing
  keyfetch.add_key_manager km
  await unbox { armored : signed_msg, keyfetch }, defer err, msg
  T.equal plaintext, msg[0].toString(), "signed literal was right"
  T.no_error err
  cb()

