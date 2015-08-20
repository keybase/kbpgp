
{KeyManager} = require '../..'

km = locked = null
passphrase = "alpha pickle foxtrot bananas"
passphrase_generation = 3

exports.gen_new_key = (T,cb) ->
  await KeyManager.generate_ecc { userid : "test@test.com" }, T.esc(defer(tmp), cb)
  km = tmp
  await km.sign {}, T.esc(defer(), cb)
  cb()

exports.lock_p3skb = (T,cb) ->
  await km.export_private { p3skb : true, passphrase, passphrase_generation }, T.esc(defer(locked), cb)
  cb()

exports.unlock_p3skb_bad_ppgen = (T,cb) ->
  await KeyManager.import_from_p3skb { armored : locked }, T.esc(defer(tmp), cb)
  km = tmp
  passphrase_generation++
  await tmp.unlock_p3skb { passphrase, passphrase_generation }, defer err
  T.assert err, "got a ppgen error"
  T.equal err.toString(), "Error: Bad passphrase generation (wanted 4 but got 3)", "right error"
  cb()

exports.unlock_p3skb = (T,cb) ->
  await KeyManager.import_from_p3skb { armored : locked }, T.esc(defer(tmp), cb)
  km = tmp
  passphrase_generation--
  await tmp.unlock_p3skb { passphrase, passphrase_generation }, defer err
  T.no_error err
  cb()