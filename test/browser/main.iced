
mods =
  fp : require '../files/fp.iced'
  nacl1 : require '../files/nacl1.iced'
  nacl2 : require '../files/nacl2.iced'
  ecc3 : require '../files/ecc3.iced'
  verify_sigs : require '../files/verify_sigs.iced'
  sigeng : require '../files/sigeng.iced'
  revoked_subkeys : require '../files/revoked_subkey.iced'
  sigs : require "../files/verify_sigs.iced"
  multiples : require "../files/multiples.iced"
  unbox_cant_verify : require '../files/unbox_cant_verify.iced'
  zip : require '../files/zip.iced'
  ecc1 : require '../files/ecc1.iced'
  ecc2 : require '../files/ecc2.iced'
  rfc3394 : require '../files/rfc3394.iced'
  google_end_to_end : require '../files/google_end_to_end.iced'
  verify_detached_sigs : require '../files/verify_detached_sigs.iced'
  hide : require '../files/hide.iced'
  critical_subpacket : require '../files/critical_subpacket.iced'
  secret_subkeys : require '../files/secret_subkeys.iced'
  secret_subkeys_incomplete : require '../files/secret_subkeys_incomplete.iced'
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

v = Object.keys(mods)
v.sort()
for k in v
  console.log k

{BrowserRunner} = require('iced-test')

window.onload = () ->
  br = new BrowserRunner { log : "log", rc : "rc" }
  await br.run mods, defer rc
