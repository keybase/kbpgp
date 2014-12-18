
{hash,ukm,kb,nacl} = require '../../'
{bufeq_fast} = require '../../lib/util'

#=================================================================

sender = recvr = ctext = null

#---------------------------------

exports.gen_eddsa = (T,cb) ->
  await nacl.dh.Pair.generate {}, T.esc(defer(tmp))
  sender = tmp
  await nacl.dh.Pair.generate {}, T.esc(defer(tmp))
  recvr = tmp
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
  cb()

#---------------------------------
