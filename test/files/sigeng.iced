
{armor,KeyManager,kb} = require '../../'

km = null

msg = """
The night attendant, a B.U. sophomore,
rouses from the mare's-nest of his drowsy head
propped on The Meaning of Meaning.
He catwalks down our corridor.
"""

sig = null
se = null

exports.generate = (T,cb) ->
  await KeyManager.generate_ecc { userid : "tester@test.cc" }, T.esc(defer(tmp), cb)
  km = tmp
  cb()

exports.box = (T,cb) ->
  se = km.make_sig_eng()
  await se.box msg, T.esc(defer(tmp), cb)
  sig = tmp
  cb()

exports.unbox = (T,cb) ->
  [ err, raw ] = armor.decode sig.pgp
  T.no_error err
  await se.unbox raw, T.esc(defer(tmp), cb)
  T.equal tmp.toString('utf8'), msg, "the right message came back out"
  cb()

exports.pgp_get_unverified_payload = (T,cb) ->
  await se.get_body_and_unverified_payload { armored : sig.pgp }, T.esc(defer(_, payload), cb)
  T.equal payload.toString('utf8'), msg, "the right message came back out"
  cb()

exports.kb_generate = (T,cb) ->
  await kb.KeyManager.generate {}, T.esc(defer(tmp), cb)
  km = tmp
  cb()

exports.kb_box = (T,cb) ->
  se = km.make_sig_eng()
  await se.box msg, T.esc(defer(tmp), cb)
  sig = tmp
  cb()

exports.kb_unbox = (T,cb) ->
  await se.unbox sig.armored, T.esc(defer(tmp), cb)
  T.equal tmp.toString('utf8'), msg, "the right message came back out"
  cb()

exports.kb_get_unverified_payload = (T,cb) ->
  await se.get_body_and_unverified_payload { armored : sig.armored }, T.esc(defer(_, payload), cb)
  T.equal payload.toString('utf8'), msg, "the right message came back out"
  cb()
