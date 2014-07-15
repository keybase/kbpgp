
{KeyManager,stream} = require '../..'

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
  T.no_error err
  buf = new Buffer planitext, 'utf8'
  await xform.write buf, defer()
  
