
{kb} = require '../../'

#====================================================

plaintext = 'It was one of those midsummer Sundays when everyone sits around saying, “I drank too much last night.”'
priv_raw = km2 = ctext = km = null

#====================================================

exports.generate_keys = (T,cb) ->
  await kb.EncKeyManager.generate {}, T.esc(defer(tmp), cb)
  km = tmp
  cb()

exports.encrypt = (T,cb) ->
  await kb.box { encrypt_for : km, msg : plaintext }, T.esc(defer(tmp))
  ctext = tmp
  cb()

exports.decrypt_1 = (T, cb) ->
  await kb.unbox { encrypt_for : km, armored : ctext}, T.esc(defer(tmp))
  T.equal tmp.plaintext.toString('utf8'), plaintext, "right plaintext"
  cb()

exports.export_private_key = (T,cb) ->
  await km.export_private {}, T.esc(defer(tmp))
  priv_raw = tmp
  cb()

exports.import_private_key = (T,cb) ->
  await kb.EncKeyManager.import_private { raw : priv_raw }, T.esc(defer(tmp))
  km2 = tmp
  cb()

exports.decrypt_2 = (T, cb) ->
  await kb.unbox { encrypt_for : km, armored : ctext}, T.esc(defer(tmp))
  T.equal tmp.plaintext.toString('utf8'), plaintext, "right plaintext"
  cb()

#====================================================

