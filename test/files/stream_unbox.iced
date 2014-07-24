
main = require '../../'
{keyring,unbox,KeyManager,stream,util} = main
{SlowFaucet,Drain} = require 'iced-stream'

#===================================================================

med = Buffer.concat ((new Buffer [0...i]) for i in [0...200])
small = Buffer.concat ((new Buffer [0...i]) for i in [0...30])

#===================================================================

oneshot = (faucet_args, xform, cb) ->
  f = new SlowFaucet faucet_args
  d = new Drain()
  f.pipe(xform)
  xform.pipe(d)
  d.once 'finish', () ->
    cb null, d.data()
  d.once 'err', (err) ->
    cb err, null
  xform.on 'error', (err) ->
    console.log "Error in transform: #{err}"

#===================================================================

R = (T, input, box_args, unbox_args, faucet_args, cb) ->
  await stream.box box_args, defer err, xform
  T.no_error err
  await oneshot { buf : input}, xform, defer err, pgp
  T.no_error err
  await stream.unbox unbox_args, defer err, xform
  xform.xbt.set_debug unbox_args.xbt_debug
  faucet_args.buf = pgp
  await oneshot faucet_args, xform, defer err, output
  if not util.bufeq_fast(input, output)
    console.log input
    console.log output
    console.log input.length
    console.log output.length
    if output.length < input.length
      if util.bufeq_fast(input[0...output.length], output)
        console.log "tis but an error of omission"
    T.assert false , "failed equality assertion"
  cb()

#===================================================================

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
km = null

#===================================================================

exports.import_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : key }, defer err, tmp
  T.no_error err
  km = tmp
  await km.unlock_pgp { passphrase }, defer err
  T.no_err
  keyfetch = new keyring.PgpKeyRing
  keyfetch.add_key_manager km
  cb()

#===================================================================

tests = 
 small_binary_literal : (T,cb)       -> R(T, small, {}, {}, {}, cb)
 small_base64_literal : (T,cb)       -> R(T, small, { opts : { armor: 'generic' }}, {}, {}, cb)
 med_binary_literal : (T,cb)         -> R(T, med, {}, {}, {}, cb)
 base64_literal : (T,cb)             -> R(T, med, { opts : { armor: 'generic' }}, {}, {}, cb)
 slow_binary_literal : (T,cb)        -> R(T, med, {}, {}, {blocksize : 137, wait_msec : 1}, cb)
 slow_base64_literal : (T,cb)        -> R(T, med, { opts : { armor : 'generic' } }, {}, {blocksize : 137, wait_msec : 1}, cb)
 small_slow_binary_literal : (T,cb)  -> R(T, small, {}, {}, {blocksize : 2, wait_msec : 3}, cb)
 small_slow_base64_literal : (T,cb)  -> R(T, small, { opts : { armor : 'generic' } }, {}, {blocksize : 1, wait_msec : 4}, cb)
 binary_compressed : (T,cb)          -> R(T, med, { opts : { compression : 'zlib' }}, {}, {}, cb)
 base64_compressed : (T,cb)          -> R(T, med, { opts : { armor: 'generic', compression : 'zlib' }}, {}, {}, cb)
 slow_binary_compressed : (T,cb)     -> R(T, med, { opts : { compression : 'zlib' }}, {}, {}, cb)
 slow_base64_compressed : (T,cb)     -> R(T, med, { opts : { armor: 'generic', compression : 'zlib' }}, {}, {blocksize: 200, wait_msec :1}, cb)
 #small_signed_literal : (T,cb)       -> R(T, small, { sign_with : km }, {}, {}, cb)

for k,v of tests
  exports[k] = v
