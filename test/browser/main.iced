
mods =  
  fermat2 : require '../files/fermat2.iced'
  miller_rabin : require '../files/miller_rabin.iced'
  rsa : require '../files/rsa.iced'

{BrowserRunner} = require('iced-test')

window.onload = () ->
  br = new BrowserRunner { log : "log", rc : "rc" }
  await br.run mods, defer rc
