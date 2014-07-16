
{KeyManager,stream} = require '../..'
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

#----------------------------------------------------------------

exports.generate_ecc_km = (T,cb) ->
  await KeyManager.generate_ecc { userid }, defer err, tmp
  T.no_error err
  km = tmp
  cb()

#----------------------------------------------------------------

exports.sign = (T,cb) ->
  await stream.box { sign_with : km }, defer err, xform
  buf = new Buffer(plaintext, 'utf8')
  await xform.write buf, defer()
  cb()

  #T.no_error err
  #f = new Faucet new Buffer(plaintext, 'utf8')
  #d = new Drain()
  #f.pipe(xform)
  #xform.pipe(d)
  #d.once 'finish', () ->
  #  console.log d.data()
  #  cb()
  #d.once 'error', (err) ->
  #  T.no_error err
  #  cb()

