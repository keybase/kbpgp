
{parse} = require '../src/packet/parser'
armor = require '../src/encode/armor'
fs = require 'fs'
C = require '../src/const'
{Processor} = require '../src/packet/processor'

await fs.readFile process.argv[2], defer err, res
throw err if err
[err,msg] = armor.decode res
throw err if err
throw new Error "need a public key" unless msg.type is C.openpgp.message_types.public_key
[err, packets] = parse msg.body
throw err if err
console.log packets
processor = new Processor packets
await processor.verify_signatures defer err
throw err if err
