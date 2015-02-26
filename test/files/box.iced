
top = require '../../'
{box,unbox,KeyManager} = top

# https://github.com/keybase/keybase-issues/issues/1415
exports.box_unbox_1 = (T,cb) ->
  await KeyManager.generate_ecc { userid : "someone" }, T.esc(defer(km), cb, "box_unbox_1")
  msg = "g'day mate"
  await box { msg, encrypt_for : km }, T.esc(defer(armored, raw), cb, "box")
  await unbox { keyfetch : km, raw }, T.esc(defer(literals), cb, "unbox")
  T.equal msg, literals[0].toString(), "literal match"
  cb()

# https://github.com/keybase/keybase-issues/issues/1415
exports.box_unbox_2 = (T,cb) ->
  F = top.const.openpgp.key_flags
  primary = {
    flags : F.certify_keys
    nbits : 768
  }
  subkeys = [{
    flags : F.encrypt_storage | F.encrypt_comm,
    nbits : 768
  },{
    flags : F.sign_data | F.auth
    nbits : 768
  }]
  userid = "joe"
  await KeyManager.generate { userid, primary, subkeys }, T.esc(defer(km), cb, "box_unbox_2")
  await km.sign {}, T.esc defer err
  msg = "g'day mate 2"
  await box { msg, encrypt_for : km }, T.esc(defer(armored, raw), cb, "box")
  await unbox { keyfetch : km, raw }, T.esc(defer(literals), cb, "unbox")
  T.equal msg, literals[0].toString(), "literal match"
  cb()

