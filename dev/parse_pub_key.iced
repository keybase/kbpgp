
{parse} = require '../src/openpgp/parser'
armor = require '../src/openpgp/armor'
fs = require 'fs'
C = require '../src/const'
{Processor} = require '../src/openpgp/processor'
util = require 'util'

await fs.readFile process.argv[2], defer err, res
throw err if err
[err,msg] = armor.decode res
throw err if err
throw new Error "need a public key" unless msg.type is C.openpgp.message_types.public_key
console.log msg.body.toString 'hex'
[err, packets] = parse msg.body
throw err if err
processor = new Processor packets
await processor.verify_signatures defer err
console.log util.inspect packets, { depth : null }
throw err if err

stripped_packets = packets[0...2] + packets[3...]