{KeyBundle} = require '../src/keybundle'
{ASP} = require '../src/util'
{make_esc} = require 'iced-error'

main = (cb) ->
  esc = make_esc cb, "main"
  asp = new ASP { }
  await KeyBundle.generate { asp, nsubs : 1, userid : 'themax' }, esc defer bundle
  await bundle.sign {asp}, esc defer()
  await bundle.export_pgp_public_to_client {asp}, esc defer pub
  console.log pub
  cb()

await main defer err
if err?
  console.log err
  process.exit -1
else
  process.exit 0

