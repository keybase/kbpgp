
top = require '../../'
{KeyManager,box} = top.kb

exports.test_wrong_key = (T,cb) ->
  await KeyManager.generate {}, T.esc(defer(km1), cb)
  await KeyManager.generate {}, T.esc(defer(km2), cb)
  se1 = km1.make_sig_eng()
  se2 = km2.make_sig_eng()
  msg = "nuts to you!"
  await se1.box msg, T.esc(defer(sig), cb)
  await se1.unbox sig.armored, T.esc(defer(payload), cb)
  T.equal msg, payload.toString(), "right payload back"
  await se2.unbox sig.armored, defer err
  T.assert err?, "got an error"
  T.assert (err instanceof top.errors.WrongSigningKeyError), "typed error came back"
  cb()


