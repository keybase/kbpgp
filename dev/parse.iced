
{parse} = require '../src/openpgp/parser'
armor = require '../src/openpgp/armor'
fs = require 'fs'
C = require '../src/const'
{KeyBlock} = require '../src/openpgp/processor'
util = require 'util'

await fs.readFile process.argv[2], defer err, res
throw err if err
[err,msg] = armor.decode res.toString('utf8')
throw err if err
switch msg.type
  when C.openpgp.message_types.public_key then console.log "Got a public key..."
  when C.openpgp.message_types.private_key then console.log "Got a private key..."
  when C.openpgp.message_types.generic then console.log "Got a generic"
  else throw new Error "unknown msg typ: #{msg.type}"
#console.log msg.body.toString 'hex'
[err, packets] = parse msg.body
throw err if err
console.log util.inspect packets, { depth : null }
#processor = new KeyBlock packets
#await processor.process defer err
#throw err if err
#console.log util.inspect packets, { depth : null }
