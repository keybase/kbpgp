
{KeyManager} = require '../..'
mk = require('../data/keys.iced').keys.mk

exports.test_mk_fp = (T,cb) ->
  opts = now : Math.floor(new Date(2015, 2, 19)/1000)
  await KeyManager.import_from_armored_pgp { armored : mk, opts }, T.esc(defer(km), cb, "load key max krohn")
  fp2 = km.get_fp2_formatted { space : 'X' }
  T.equal fp2, "8EFBXE2E4XDD56XB352X7363XX4E8FX6052XB2ADX31A6X631C", "max's fingerprint was right"
  cb()
