kbpgp = require '../..'
{KeyManager} = kbpgp
{seal,unseal,read_base64} = kbpgp.kb.encode

km = locked = null
passphrase = "alpha pickle foxtrot bananas"
passphrase_generation = 3

exports.gen_new_key = (T,cb) ->
  await KeyManager.generate_ecc { userid : "test@test.com" }, T.esc(defer(tmp), cb)
  km = tmp
  await km.sign {}, T.esc(defer(), cb)
  cb()

exports.lock_p3skb = (T,cb) ->
  await km.export_private { p3skb : true, passphrase, passphrase_generation }, T.esc(defer(tmp), cb)
  locked = tmp
  cb()

exports.unlock_p3skb_bad_ppgen = (T,cb) ->
  await KeyManager.import_from_p3skb { armored : locked }, T.esc(defer(tmp), cb)
  km = tmp
  passphrase_generation++
  await tmp.unlock_p3skb { passphrase : (passphrase + "a"), passphrase_generation }, defer err
  T.assert err, "got a ppgen error"
  righterr = "Error: Decryption failed, likely due to old passphrase (wanted v4 but got v3) [Error: Signature mismatch or bad decryption key]"
  T.equal err.toString(), righterr, "right error"
  cb()

exports.unlock_p3skb = (T,cb) ->
  await KeyManager.import_from_p3skb { armored : locked }, T.esc(defer(tmp), cb)
  km = tmp
  passphrase_generation--
  await tmp.unlock_p3skb { passphrase, passphrase_generation }, defer err
  T.no_error err
  cb()

exports.unlock_p3skb_unknown_encryption_type = (T,cb) ->
  buf = unseal(read_base64(locked))
  buf.body.priv.encryption = 999
  armored = seal({obj : buf}).toString('base64')
  await KeyManager.import_from_p3skb { armored }, T.esc(defer(tmp), cb)
  await tmp.unlock_p3skb { passphrase, passphrase_generation }, defer err
  T.assert err?, "got an unknown encryption error"
  T.equal err.toString(), "Error: Unknown key encryption type: 999", "right error"
  cb()
