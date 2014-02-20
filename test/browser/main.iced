
mods =  
  elgamal : require '../files/elgamal.iced'
  dsa : require '../files/dsa.iced'
  buffer_shfit_right : require '../files/buffer_shift_right.iced' 
  verify_clearsign_sigs : require '../files/verify_clearsign_sigs.iced'
  decoder : require '../files/decoder.iced'
  userid : require '../files/userid.iced'
  msg_roundtrip : require '../files/msg_roundtrip.iced'
  decrypt_verify_msg : require '../files/decrypt_verify_msg.iced'
  keymanager : require '../files/keymanager.iced'
  decode_pgp : require '../files/decode_pgp.iced'
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
