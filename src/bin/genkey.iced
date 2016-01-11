
kbpgp = require '../..'
fs = require 'fs'
minimist = require 'minimist'
{make_esc} = require 'iced-error'

class Runner

  constructor : (@argv) ->

  run : (cb) ->
    esc = make_esc cb, "run"
    await kbpgp.KeyManager.generate_rsa { userids : [] }, esc defer km
    await km.sign {}, esc defer()
    await km.export_pgp_public {}, esc defer exp
    console.log exp
    cb null

main = (cb) ->
  r = new Runner process.argv[2...]
  await r.run defer err
  cb err

await main defer err
if err?
  console.error err.toString()
  process.exit 2

