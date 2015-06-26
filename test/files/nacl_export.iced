
{kb} = require '../../'

#====================================================

plaintext = 'It was one of those midsummer Sundays when everyone sits around saying, “I drank too much last night.”'
priv_raw = km2 = ctext = km = null

#====================================================

exports.enc_generate_keys = (T,cb) ->
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

exports.enc_export_private_key = (T,cb) ->
  await km.export_private {}, T.esc(defer(tmp))
  priv_raw = tmp
  cb()

exports.enc_import_private_key = (T,cb) ->
  await kb.EncKeyManager.import_private { raw : priv_raw }, T.esc(defer(tmp))
  km2 = tmp
  cb()

exports.decrypt_2 = (T, cb) ->
  await kb.unbox { encrypt_for : km, armored : ctext}, T.esc(defer(tmp))
  T.equal tmp.plaintext.toString('utf8'), plaintext, "right plaintext"
  cb()

#====================================================

exports.sig_generate_keys = (T,cb) ->
  await kb.KeyManager.generate {}, T.esc(defer(tmp), cb)
  km = tmp
  cb()

exports.sign_1 = (T,cb) ->
  await kb.box { sign_with : km, msg : plaintext }, T.esc(defer(tmp))
  ctext = tmp
  cb()

exports.verify_1 = (T, cb) ->
  await kb.unbox { armored : ctext}, T.esc(defer(tmp))
  T.equal tmp.payload.toString('utf8'), plaintext, "right plaintext"
  T.assert tmp.km.eq(km), "right key"
  cb()

exports.sig_export_private_key = (T,cb) ->
  await km.export_private {}, T.esc(defer(tmp))
  priv_raw = tmp
  cb()

exports.sig_import_private_key = (T,cb) ->
  await kb.KeyManager.import_private { raw : priv_raw }, T.esc(defer(tmp))
  km2 = tmp
  cb()

exports.sign_2 = (T,cb) ->
  await kb.box { sign_with : km2, msg : plaintext }, T.esc(defer(tmp))
  ctext = tmp
  cb()

exports.verify_2 = (T, cb) ->
  await kb.unbox { armored : ctext}, T.esc(defer(tmp))
  T.equal tmp.payload.toString('utf8'), plaintext, "right plaintext"
  T.assert tmp.km.eq(km), "right key"
  cb()

#====================================================

