{KeyManager} = require '../src/keymanager'
{bufferify,ASP} = require '../src/util'
{make_esc} = require 'iced-error'
util = require 'util'
{box} = require '../src/keybase/encode'
{Encryptor} = require 'triplesec'
 
progress_hook = (obj) ->
  if obj.p?
    s = obj.p.toString()
    s = "#{s[0...3]}....#{s[(s.length-6)...]}"
  else
    s = ""
  interval = if obj.total? and obj.i? then "(#{obj.i} of #{obj.total})" else ""
  console.warn "+ #{obj.what} #{interval} #{s}"

main = (cb) ->
  esc = make_esc cb, "main"
  tsenc = new Encryptor { key : bufferify("shitty"), version : 2 }
  asp = new ASP { progress_hook }
  await KeyManager.generate { asp, nbits : 1024, nsubs : 1, userid : 'maxtaco@keybase.io' }, esc defer bundle
  await bundle.sign {asp}, esc defer()
  #await bundle.export_private_to_server {tsenc,asp}, esc defer pair
  await bundle.export_pgp_private_to_client { passphrase : "cats", asp }, esc defer msg
  #console.log util.inspect(pair, { depth : null })
  #console.log box(pair.keybase).toString('base64')
  console.log msg
  cb()

await main defer err
if err?
  console.log err
  process.exit -1
else
  process.exit 0

