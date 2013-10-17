{KeyManager} = require '../src/keymanager'
{ASP} = require '../src/util'
{make_esc} = require 'iced-error'

main = (cb) ->
  esc = make_esc cb, "main"
  asp = new ASP { }
  await KeyManager.generate { asp, nbits : 1024, nsubs : 1, userid : 'maxtaco@keybase.io' }, esc defer bundle
  await bundle.sign_pgp {asp}, esc defer()
  await bundle.export_pgp_public_to_client {asp}, esc defer pub
  console.log pub
  cb()

await main defer err
if err?
  console.log err
  process.exit -1
else
  process.exit 0

