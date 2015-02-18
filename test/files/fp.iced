
{KeyManager} = require '../..'
mk = require('../data/keys.iced').keys.mk

exports.test_mk_fp = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : mk }, T.esc(defer(km), cb, "load key max krohn")
  fp2 = km.get_fp2_formatted { space : 'X' }
  T.equal fp2, "8EFBXE2E4XDD56XB352X7363XX4E8FX6052XB2ADX31A6X631C", "max's fingerprint was right"
  cb()
