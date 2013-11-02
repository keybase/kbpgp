#!/usr/bin/env iced

fs = require 'fs'
{make_esc} = require 'iced-error'
armor = require '../lib/openpgp/armor'
util = require '../lib/util'
{Message} = require '../lib/openpgp/processor'
{PgpKeyRing} = require '../lib/keyring'
{KeyManager} = require '../lib/keymanager'

#=================================================================

class Runner
  constructor : ({@msgfile, @keyfile, @passphrase}) ->
    @ring = new PgpKeyRing

  _read_file : (fn, cb) ->
    esc = make_esc cb, "read_file #{fn}"
    await fs.readFile fn, esc defer data
    [err, msgs] = armor.mdecode data
    await util.athrow err, esc defer()
    cb null, msgs

  read_keys : (cb) ->
    esc = make_esc cb, "read_keys"
    await @_read_file @keyfile, esc defer msgs
    asp = new util.ASP {}
    userid = "anon@keybase.io"
    for msg in msgs
      await KeyManager.import_from_pgp_message { msg, asp, userid }, esc defer km
      if km.is_pgp_locked()
        await km.unlock_pgp { @passphrase }, esc defer()
      @ring.add_key_manager km
    cb null

  read_msg : (cb) ->
    esc = make_esc cb, "read_msg"
    await @_read_file @msgfile, esc defer msgs
    @msg = msgs[0]
    cb null

  process : (cb) ->
    esc = make_esc cb, "process"
    proc = new Message @ring
    await proc.parse_and_process @msg.body, esc defer literals
    console.log literals
    for l in literals
      console.log l.toString()
    cb null

  run : (cb) ->
    esc = make_esc cb, "run"
    await @read_keys esc defer()
    await @read_msg esc defer()
    await @process esc defer()
    cb null

#=================================================================

argv = require('optimist')
       .alias("m", "msg")
       .alias("k","keyfile")
       .alias("s", "sign")
       .boolean("s")
       .alias("e", "encrypt")
       .boolean("e")
       .usage("$0 -m <msg> -k <keyfile> -p <passphrase> -s -e")
       .alias("p","passphrase").argv

#=================================================================

ok = false
if not argv.msg?
  console.error "need a msg file to operate on"
else if not argv.keyfile?
  console.error "need a keyfile to read keys from "
else if (argv.s or not argv.e) and not argv.passphrase
  console.error "need a passphrase to unlock a signing or decrypting key"
else
  ok = true

process.exit -1 unless ok

#=================================================================

runner = new Runner { msgfile : argv.m, keyfile : argv.k, passphrase : argv.p }
await runner.run defer err
throw err if err?
process.exit 0