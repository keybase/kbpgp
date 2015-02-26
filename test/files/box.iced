
{box,unbox,KeyManager} = require '../../'

# https://github.com/keybase/keybase-issues/issues/1415
exports.box_unbox_1 = (T,cb) ->
  await KeyManager.generate_ecc { userid : "someone" }, T.esc(defer(km), cb, "box_unbox_1")
  msg = "g'day mate"
  await box { msg, encrypt_for : km }, T.esc(defer(armored, raw), cb, "box")
  await unbox { keyfetch : km, raw }, T.esc(defer(literals), cb, "unbox")
  T.equal msg, literals[0].toString(), "literal match"
  cb()

