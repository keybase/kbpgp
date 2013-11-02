#!/usr/bin/env iced

fs = require 'fs'
{make_esc} = require 'iced-error'
armor = require '../lib/openpgp/armor'
util = require '../lib/util'
{Message} = require '../lib/openpgp/processor'
{PgpKeyRing} = require '../lib/keyring'
{KeyManager} = require '../lib/keymanager'

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

class Runner
  constructor : (@argv) ->
    @ring = new PgpKeyRing

  _read_file : (fn, cb) ->
    esc = make_esc cb, "read_file #{fn}"
    await fs.readFile fn, esc defer data
    [err, msgs] = armor.mdecode data
    await util.athrow err, esc defer()
    cb null, msgs

  read_keys : (cb) ->
    esc = make_esc cb, "read_keys"
    await @_read_file @argv.keyfile, esc defer msgs
    asp = new util.ASP {}
    userid = "anon@keybase.io"
    for msg in msgs
      await KeyManager.import_from_pgp_message { msg, asp, userid }, esc defer km
      if km.is_pgp_locked() and @need_private_keys()
        await km.unlock_pgp { passphrase : @argv.passphrase }, esc defer()
      @ring.add_key_manager km
    cb null

  read_msg : (cb) ->
    esc = make_esc cb, "read_msg"
    await @_read_file @argv.msg, esc defer msgs
    @msg = msgs[0]
    cb null

  from_pgp : (cb) ->
    esc = make_esc cb, "process"
    proc = new Message @ring
    await proc.parse_and_process @msg.body, esc defer literals
    console.log literals
    for l in literals
      console.log l.toString()
    cb null

  to_pgp : (cb) ->
    cb null

  need_private_keys : () -> (not @do_to_pgp()) or @argv.s
  do_to_pgp : () -> @argv.s or @argv.e

  parse_args : (cb) ->
    ok = false
    err = if not @argv.msg?
      new Error "need a msg file to operate on"
    else if not @argv.keyfile?
      new Error "need a keyfile to read keys from"
    else if @need_private_keys() and not @argv.passphrase
      new Error "need a passphrase to unlock a signing or decrypting key"
    else
      null
    cb err

  run : (cb) ->
    esc = make_esc cb, "run"
    await @parse_args esc defer()
    await @read_keys esc defer()
    await @read_msg esc defer()
    if @do_to_pgp()
      await @to_pgp esc defer()
    else
      await @from_pgp esc defer()
    cb null

#=================================================================

runner = new Runner argv 
await runner.run defer err
throw err if err?
process.exit 0