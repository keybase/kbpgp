
mods = 
  sig_various_hashes : require '../files/sig_various_hashes.iced'
  openpgp_js_cure53_audit : require '../files/openpgp_js_cure53_audit.iced'
  bzip2 : require '../files/bzip2.iced'
  decode_pgp : require '../files/decode_pgp.iced'
  get_primary_uid : require '../files/get_primary_uid.iced'
  sig_v3 : require '../files/sig_v3.iced'
  sig_gocli : require '../files/sig_gocli.iced'
  elgamal : require '../files/elgamal.iced'
  dsa : require '../files/dsa.iced'
  rsa_8192 : require '../files/rsa_8192.iced'
  buffer_shfit_right : require '../files/buffer_shift_right.iced' 
  verify_clearsign_sigs : require '../files/verify_clearsign_sigs.iced'
  decoder : require '../files/decoder.iced'
  userid : require '../files/userid.iced'
  msg_roundtrip : require '../files/msg_roundtrip.iced'
  decrypt_verify_msg : require '../files/decrypt_verify_msg.iced'
  keymanager : require '../files/keymanager.iced'
  cast5 : require '../files/cast5.iced'
  basex : require '../files/basex.iced'
  cfb : require '../files/cfb.iced'
  fermat2 : require '../files/fermat2.iced'
  miller_rabin : require '../files/miller_rabin.iced'
  rsa : require '../files/rsa.iced'

{BrowserRunner} = require('iced-test')

window.onload = () ->
  br = new BrowserRunner { log : "log", rc : "rc" }
  await br.run mods, defer rc
