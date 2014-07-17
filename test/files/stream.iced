
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

box = ({T,sign_with, encrypt_for,plaintext,opts}, cb) ->
  opts or= {}
  await stream.box { sign_with, encrypt_for, opts}, defer err, xform
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

unbox2 = ({T,plaintext, armored, km, signed }, cb) ->
  await unbox { armored, keyfetch }, defer err, msg
  T.no_error err
  T.equal plaintext, msg[0].toString(), "output literal was right"
  if signed
    T.assert km.is_pgp_same_key(msg[0].get_data_signer().km, km), "the right signing key"
  cb()

#----------------------------------------------------------------

round_trip = (cfg, T,plaintext,cb) ->
  arg = { T, km, plaintext }
  for c in cfg
    switch c
      when 's' 
        arg.sign_with = km
        arg.signed = true
      when 'e'
        arg.encrypt_for = km
      when 'z'
        arg.opts = { compression : 'zlib' } 
  await box arg, defer arg.armored
  T.waypoint "sign"
  await unbox2 arg, defer()
  T.waypoint "verify"
  cb()

#----------------------------------------------------------------

exports.encrypt_shortie = (T,cb) -> round_trip "e", T, short, cb
exports.encrypt_med = (T,cb) -> round_trip "e", T, med, cb
exports.encrypt_med_zlib = (T,cb) -> round_trip "ez", T, med, cb

#----------------------------------------------------------------

exports.sign_and_verify_shortie = (T,cb) -> round_trip "s", T, short, cb
exports.sign_and_verify_med = (T,cb) -> round_trip "s", T, med, cb
exports.sign_and_verify_zlib = (T,cb) -> round_trip "sz", T, med, cb

#----------------------------------------------------------------

exports.signcrypt_shortie = (T,cb) -> round_trip "es", T, short, cb
exports.signcrypt_med = (T,cb) -> round_trip "es", T, med, cb
exports.signcrypt_zlib = (T,cb) -> round_trip "esz", T, med, cb

#----------------------------------------------------------------
