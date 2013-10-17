{KeyManager} = require '../src/keymanager'
{ASP} = require '../src/util'
{make_esc} = require 'iced-error'
 
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
  asp = new ASP { progress_hook }
  await KeyManager.generate { asp, nbits : 1024, nsubs : 1, userid : 'maxtaco@keybase.io' }, esc defer bundle
  await bundle.sign {asp}, esc defer()
  await bundle.export_private_to_server {asp}, esc defer pair
  console.log pair
  cb()

await main defer err
if err?
  console.log err
  process.exit -1
else
  process.exit 0

