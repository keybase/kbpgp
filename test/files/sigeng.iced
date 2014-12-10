
{armor,KeyManager} = require '../../'

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
  await se.box  msg, T.esc(defer(tmp), cb)
  sig = tmp
  cb()

exports.unbox = (T,cb) ->
  [ err, raw ] = armor.decode sig.pgp
  T.no_error err
  await se.unbox raw, T.esc(defer(tmp), cb)
  T.equal tmp.toString('utf8'), msg, "the right message came back out"
  cb()

