
kbpgp = require '../..'
fs = require 'fs'
minimist = require 'minimist'
{make_esc} = require 'iced-error'

class Runner

  constructor : (@argv) ->

  parse_argv : (cb) ->
    err = null
    argv = minimist @argv
    if argv._.length != 1
      err = new Error "usage: importkey <file>"
    else
      @file = argv._[0]
    cb err

  run_file : (cb) ->
    esc = make_esc cb, "run_file"
    await fs.readFile @file, esc defer armored
    await kbpgp.KeyManager.import_from_armored_pgp { armored }, esc defer ret, warnings, packets
    console.log warnings.warnings()
    console.log packets
    cb null

  run : (cb) ->
    esc = make_esc cb, "run"
    await @parse_argv esc defer()
    await @run_file esc defer()
    cb null

main = (cb) ->
  r = new Runner process.argv[2...]
  await r.run defer err
  cb err

await main defer err
if err?
  console.error err.toString()
  process.exit 2

