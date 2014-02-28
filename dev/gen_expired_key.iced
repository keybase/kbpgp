{KeyManager} = require '../lib/keymanager'
{make_esc} = require 'iced-error'
argv = require('minimist')(process.argv[2...])

#=======================================================

run = (cb) ->
  esc = make_esc cb, "run"
  await KeyManager.generate { nsubs : 1, userid : argv._[0], nbits : 1024 }, esc defer km
  # Hack the expiration timer
  km.pgp.primary.lifespan.expire_in = v if (v = argv.p)?
  km.pgp.subkeys[0].lifespan.expire_in = v if (v = argv.s)?
  await km.sign {}, esc defer()
  await km.export_pgp_public {}, esc defer msg
  cb null, msg

await run defer err, msg
console.log (err or msg)
process.exit 0

