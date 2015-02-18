
{hash,ukm,kb,nacl} = require '../../'
{base64u,bufeq_fast} = require '../../lib/util'

#=================================================================

sender = recvr = charlie = ctext = null
skm = rkm = null

#---------------------------------

exports.gen_eddsa = (T,cb) ->
  tmp = []
  for i in [0...3]
    await nacl.dh.Pair.generate {}, T.esc(defer(tmp[i]))
  [ sender, recvr, charlie ] = tmp
  cb()

#---------------------------------

msg = new Buffer """To the Congress of the United States: Yesterday, Dec. 7, 1941 - a
date which will live in infamy - the United States of America was suddenly and
deliberately attacked by naval and air forces of the Empire of Japan.""", "utf8"

#---------------------------------

exports.encrypt_1 = (T, cb) ->
  await recvr.encrypt_kb { plaintext : msg, sender }, T.esc(defer(tmp), cb)
  ctext = tmp
  cb()

#---------------------------------

exports.verify_attached_1 = (T, cb) ->
  args = 
    ciphertext : ctext.ciphertext
    nonce : ctext.nonce
    sender : sender
  await recvr.decrypt_kb args, T.esc(defer(out), cb)
  T.assert bufeq_fast(out, msg), "got right payload back"
  args.ciphertext[30]++
  await recvr.decrypt_kb args, defer err
  T.assert err?, "error happened after we corrupted the ciphertext"
  args.ciphertext[30]--
  args.sender = charlie
  await recvr.decrypt_kb args, defer err
  T.assert err?, "error happened after we used the wrong sender key"
  cb()

#---------------------------------

exports.box_1 = (T,cb) ->
  rkm = new kb.EncKeyManager { key : recvr }
  skm = new kb.EncKeyManager { key : sender }
  await kb.box { msg, sign_with : skm, encrypt_for : rkm }, T.esc(defer(tmp), cb)
  ctext = tmp
  cb()

#---------------------------------

exports.km = (T,cb) ->
  typ = skm.get_type()
  fp2 = skm.get_fp2_formatted { space : ' ' }
  T.equal typ, "kb", "keymanager type was right"
  T.equal base64u.encode(skm.get_ekid()).indexOf(fp2), 0, "found fingerprint"
  cb()

#---------------------------------

exports.unbox_1 = (T,cb) ->
  await kb.unbox { armored : ctext, encrypt_for : rkm }, T.esc(defer(tmp), cb)
  T.assert bufeq_fast(tmp.plaintext, msg), "decrypted properly"
  cb()

#---------------------------------

exports.box_2 = (T,cb) ->
  await kb.box { msg, encrypt_for : rkm }, T.esc(defer(tmp), cb)
  ctext = tmp
  cb()

#---------------------------------

exports.unbox_2 = (T,cb) ->
  await kb.unbox { armored : ctext, encrypt_for : rkm }, T.esc(defer(tmp), cb)
  T.assert bufeq_fast(tmp.plaintext, msg), "decrypted properly"
  cb()

#---------------------------------

exports.box_3 = (T,cb) ->
  await kb.box { msg, encrypt_for : rkm, anonymous : true }, T.esc(defer(tmp), cb)
  ctext = tmp
  cb()

#---------------------------------

exports.unbox_3 = (T,cb) ->
  await kb.unbox { armored : ctext, encrypt_for : rkm }, T.esc(defer(tmp), cb)
  T.assert bufeq_fast(tmp.plaintext, msg), "decrypted properly"
  cb()

#---------------------------------

exports.unbox_split_seed_1 = (T,cb) ->
  seed = hash.SHA256 new Buffer "this be the password; don't leak it!", "utf8"
  await kb.EncKeyManager.generate { split : true, seed }, T.esc(defer(km3), cb)
  await kb.box { msg, encrypt_for : km3 }, T.esc(defer(a), cb)
  await kb.unbox { armored : a, encrypt_for : km3 }, T.esc(defer(p), cb)
  T.assert bufeq_fast(p.plaintext, msg), "decrypted properly"
  await kb.EncKeyManager.generate { split : true, seed, server_half : km3.server_half }, T.esc(defer(km4), cb)
  await kb.unbox { armored : a, encrypt_for : km4 }, T.esc(defer(p), cb)
  T.assert bufeq_fast(p.plaintext, msg), "decrypted properly"
  cb()

