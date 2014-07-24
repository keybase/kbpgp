
main = require '../../'
{keyring,unbox,KeyManager,stream,util} = main
C = main.const
{Faucet,SlowFaucet,Drain} = require 'iced-stream'

#----------------------------------------------------------------

km = null
short = """
Calmly we walk through this April's day,
Metropolitan poetry here and there,
In the park sit pauper and rentier,
The screaming children, the motor-car
""" + "\n"
med = "".concat (short for [0...10000])...
userid = "Delmore Schwartz"
keyfetch = null

key = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQHYBFPIMaQBBADaOJTBesYpRd8dQiVd11pbbss5PwSKYeQ8LUTeTgRq14I8Nikg
uWCxd75lTft3vLpmQX1iCLX04aSXV8r479jG0IPorgGmWOxSSXni44AtkBmVjkUS
k2YyHyar5hsx7lmTFcEKuBl8nFe0b3+KCvmQHIFMU6ZSPQiWWU4XOYJ65wARAQAB
AAP9Fl6CcSrisUxmSJuFNQ9kRccfseiR0JWkTb7eNmOM9F7PDNkIckBOdyKtM7lA
s8921BCWh7wY2tdehd0MA2Sitd4fPPuxtWuxirou6XUKP2oYQZML2ipTrjKKU2LD
+LO2uAq0pRnlxkshqbuWocLUixRoF7vcIpkUQw+AS86fPjECAOMr0Rnifdv99NW4
jO/UE2QWUYY1Ah7jVsIBq/9U92FYmROx7RSXp49PsOh0EMFnWg29llI9PEzhO2Vv
KoxzSwUCAPXp/4kyZclCkIaEdIPg+hK4+HRiLQc6NK1ghmBIWEkyODhL8PUFmPXd
OarZ4kDfCZbWJjFuBaiOiuZUUbMdyfsB/2S57Y4sDROnOMLBevpJMbaBRN5EcKpk
Q8DVKe9S5TJHlPv2FiT7rO2xASVwkFbeVoQGIRueSVjtyqolRPAf6SmfM7QQRGVs
bW9yZSBTY2h3YXJ0eoi4BBMBCgAiBQJTyDGkAhsDBgsJCAcDAgYVCAIJCgsEFgID
AQIeAQIXgAAKCRCbZTvdDU+8dm8rA/0RzUO1sTaa3WboASQL2Bs1WC8YS8j+CSQ6
mxuSSd+dDozOGb/R+JtpjVVtd+hLsBssEJ2p966CqxGucdTQp2Q4Yo5KqhSg6vMx
tPv3Jdw6VbcHw74rAv+cD4cQfhUgl6SsCwTrD7GRQA5ZcHHBMGjM9QRL4tPdgXNh
NuldF5IGdp0B2ARTyDGkAQQAn7Q0KVwXoDHKrDyUuVDkcGNS7Pws1MfaVkiFoKfj
ORSz3FVFaMBWZcYloICsBoStmXzCe/sTlBji2cPr0dc1tQIAdi6V+LSqLJ4zL++K
RGO4ktOi+XInsDo1G8u6kvEz8dwaQsIllrT5j0nQX/2np34x3x/mqsD+UnEF9yrs
51kAEQEAAQAD+gJ4BZDonaxiLKsINjfdrGRg4rKrbNF+w+0uypMK2WBD5cpnjo7B
n2xMGX+PUal5olnjs/l47ors7g/V/6ajLC85hwHeKgeK5OHiau7wdISHsmtteaxO
hCo0OhjaziGJQHfHeZsxw7D39Q6u8/yw8cIGYpOog/NJ//j6I8uv9hixAgDDgXR1
EkoPo3OzRDIn4I2qFtWOSFu/AIEsa4mcB/UqYJYS1bp4FWn5icWYLT9huE0Mtlec
mH0b/h4dvnKtNfrpAgDRHsrZWMzT+y+6v6Y4v+wM30ST8dbKP8vfD0JtGnpN4kpl
pQPCBaEmcQwdjZziMaCXCyMsm4RsHMuHKyJiiuLxAf90jSeiwM/r0GniVzG+qhjs
Lol4BTqb/mhGgIPTyGnKEQmHXTdX+s/FVQXRXJm5whaqMH5AhbmOQtc6TtdfA8cH
pfeInwQYAQoACQUCU8gxpAIbDAAKCRCbZTvdDU+8drwVBACry8ODpFawonDIoCQ3
kvXeO/tyKwWUc8roA/kcHR3IgFdkrRpwcmFXtmU2f+cOD8K/wsOejuA6q7ojqCuZ
QV99g9VQROulnIj0QkKYpAyULZP8jcCstLLqt1AFhBc5XQBpVrObLiO9KJFPC5Su
DyUeXyPKdqJfJNtvfM2wwd5P5g==
=1AKw
-----END PGP PRIVATE KEY BLOCK-----
"""
passphrase = ""

#----------------------------------------------------------------

exports.import_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, tmp
  T.no_error err
  km = tmp
  await km.unlock_pgp { passphrase }, defer err
  T.no_err
  keyfetch = new keyring.PgpKeyRing
  keyfetch.add_key_manager km
  cb()

#----------------------------------------------------------------

box = ({T,sign_with, encrypt_for,plaintext,opts}, cb) ->
  opts or= {}
  opts.armor = 'generic'
  await stream.box { sign_with, encrypt_for, opts}, defer err, xform
  T.no_error err
  buf = new Buffer(plaintext, 'utf8')
  f = new SlowFaucet { buf, blocksize : 1024*16, wait_msec : 0 }
  d = new Drain()
  f.pipe(xform)
  xform.pipe(d)
  d.once 'finish', () ->
    buf = d.data()
    signed_msg = buf
    cb signed_msg
  d.once 'error', (err) ->
    T.no_error err
    cb()

#----------------------------------------------------------------

unbox2 = ({T,plaintext, armored, km, signed }, cb) ->
  await unbox { armored, keyfetch }, defer err, msg
  T.no_error err
  throw err if err?
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
  T.waypoint "box"
  await unbox2 arg, defer()
  T.waypoint "unbox"
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
