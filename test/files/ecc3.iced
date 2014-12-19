
top = require '../..'
{KeyManager,ecc} = top
C = top.const.openpgp

#===========================================

armored = km = null

#===========================================

exports.generate_p521 = (T,cb) ->
  userid = "test3@test.cc"
  F = C.key_flags
  primary = {
    flags : F.certify_keys
    nbits : 521
    algo : ecc.ECDSA
  }
  subkeys = [{
    flags : F.encrypt_data | F.encrypt_comm,
    nbits : 384
  },{
    flags : F.sign_data | F.auth
    nbits : 384
  }]

  await KeyManager.generate { userid, primary, subkeys }, T.esc(defer(tmp),cb)
  km = tmp
  cb()

#===========================================

exports.export_key = (T,cb) ->
  await km.sign {}, T.esc(defer(tmp), cb)
  await km.export_public {}, T.esc(defer(tmp), cb)
  armored = tmp
  cb()

#===========================================

exports.import_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored }, T.esc(defer(km2), cb)
  cb()

#===========================================

