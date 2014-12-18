
{hash,ukm,kb,nacl} = require '../../'
{bufeq_fast} = require '../../lib/util'

#=================================================================

dsig = asig = pair = null

#---------------------------------

exports.gen_eddsa = (T,cb) ->
  await nacl.eddsa.Pair.generate {}, T.esc(defer(tmp))
  pair = tmp
  cb()

#---------------------------------

msg = new Buffer """To the Congress of the United States: Yesterday, Dec. 7, 1941 - a
date which will live in infamy - the United States of America was suddenly and
deliberately attacked by naval and air forces of the Empire of Japan.""", "utf8"

#---------------------------------

exports.sign_attached_1 = (T, cb) ->
  await pair.sign_kb { payload : msg, detached : false }, T.esc(defer(tmp), cb)
  asig = tmp
  cb()

#---------------------------------

exports.verify_attached_1 = (T, cb) ->
  await pair.verify_kb { sig : asig, detached : false }, T.esc(defer(out), cb)
  T.assert bufeq_fast(out, msg), "got right payload back"

  # Verify and check that the right payload was inside
  await pair.verify_kb { sig : asig, detached : false, payload : msg }, T.esc(defer(out), cb)

  msg2 = new Buffer msg
  msg2[0]++
  await pair.verify_kb { sig : asig, detached : false, payload : msg2 }, defer err, out
  T.assert err?, "get an error if the payload is wrong"

  asig2 = new Buffer asig
  asig2[10]++
  await pair.verify_kb { sig : asig2, detached : false, payload : msg }, defer err, out
  T.assert err?, "get an error if the sig s wrong"

  cb()

#---------------------------------

exports.sign_detached_1 = (T,cb) ->
  await pair.sign_kb { payload : msg, detached : true }, T.esc(defer(tmp), cb)
  dsig = tmp
  cb()

#---------------------------------

exports.verify_dettached_1 = (T, cb) ->
  await pair.verify_kb { sig : dsig, detached : true, payload : msg}, T.esc(defer(out), cb)

  msg2 = new Buffer msg
  msg2[0]++
  await pair.verify_kb { sig : dsig, detached : true, payload : msg2 }, defer err, out
  T.assert err?, "get an error if the payload is wrong"

  dsig2 = new Buffer dsig
  dsig2[10]++
  await pair.verify_kb { sig : dsig2, detached : true, payload : msg }, defer err, out
  T.assert err?, "get an error if the sig s wrong"

  cb()

#---------------------------------

km = null
boxed = null
exports.box1 = (T,cb) ->
  km = new kb.KeyManager { key : pair }
  await kb.box { msg, sign_with : km }, T.esc(defer(out), cb)
  boxed = out
  cb()

#---------------------------------

exports.unbox1 = (T,cb) ->
  await kb.unbox { armored : boxed }, T.esc(defer(out), cb)
  T.assert out.km.eq(km), "the same keymanager came back"
  T.assert bufeq_fast(out.payload, msg), "the same message came back"
  cb()

#---------------------------------

exports.exim1 = (T,cb) ->
  await km.export_public {}, T.esc(defer(armored), cb)
  await ukm.import_armored_public { armored }, T.esc(defer(km2), cb)
  T.assert km.check_public_eq(km2), "equality of keymanagers achieved"
  cb()

#---------------------------------

exports.sigeng1 = (T,cb) ->
  se = km.make_sig_eng()
  await se.box msg, T.esc(defer(res), cb)
  await se.unbox res.armored, T.esc(defer(msg2), cb)
  T.equal msg, msg2, "the right msg came back"
  cb()

#---------------------------------

reggen_eddsa_2 = (T,cb) ->
  seed = hash.SHA256 new Buffer "this be the password; don't leak it!", "utf8"
  await nacl.eddsa.Pair.generate {seed}, T.esc(defer(tmp))
  cb tmp

#---------------------------------

exports.sign_attached_2 = (T, cb) ->
  await reggen_eddsa_2 T, defer k
  await k.sign_kb { payload : msg, detached : false }, T.esc(defer(tmp), cb)
  asig = tmp
  cb()

#---------------------------------

exports.verify_attached_2 = (T, cb) ->
  await reggen_eddsa_2 T, defer k

  await k.verify_kb { sig : asig, detached : false }, T.esc(defer(out), cb)
  T.assert bufeq_fast(out, msg), "got right payload back"

  # Verify and check that the right payload was inside
  await k.verify_kb { sig : asig, detached : false, payload : msg }, T.esc(defer(out), cb)

  msg2 = new Buffer msg
  msg2[0]++
  await k.verify_kb { sig : asig, detached : false, payload : msg2 }, defer err, out
  T.assert err?, "get an error if the payload is wrong"

  asig2 = new Buffer asig
  asig2[10]++
  await k.verify_kb { sig : asig2, detached : false, payload : msg }, defer err, out
  T.assert err?, "get an error if the sig s wrong"

  cb()

#---------------------------------

server_half = null

reggen_eddsa_3 = (T,cb) ->
  seed = hash.SHA256 new Buffer "this be the password; don't leak it!", "utf8"
  await nacl.eddsa.Pair.generate {seed, split : true, server_half}, T.esc(defer(tmp, tmp2), cb)
  server_half = tmp2
  cb tmp

#---------------------------------

exports.sign_attached_3 = (T, cb) ->
  await reggen_eddsa_3 T, defer k
  await k.sign_kb { payload : msg, detached : false }, T.esc(defer(tmp), cb)
  asig = tmp
  cb()

#---------------------------------

exports.verify_attached_3 = (T, cb) ->
  await reggen_eddsa_3 T, defer k

  await k.verify_kb { sig : asig, detached : false }, T.esc(defer(out), cb)
  T.assert bufeq_fast(out, msg), "got right payload back"

  # Verify and check that the right payload was inside
  await k.verify_kb { sig : asig, detached : false, payload : msg }, T.esc(defer(out), cb)

  msg2 = new Buffer msg
  msg2[0]++
  await k.verify_kb { sig : asig, detached : false, payload : msg2 }, defer err, out
  T.assert err?, "get an error if the payload is wrong"

  asig2 = new Buffer asig
  asig2[10]++
  await k.verify_kb { sig : asig2, detached : false, payload : msg }, defer err, out
  T.assert err?, "get an error if the sig s wrong"

  cb()

#---------------------------------
