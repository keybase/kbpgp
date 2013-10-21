
mods =  
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
