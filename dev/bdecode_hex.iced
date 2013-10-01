
fs = require 'fs'
util = require 'util'
{bdecode} = require '../src/kbpacket/encode'

strip = (x) ->
  v = x.split /\s+/
  v.join ''

await fs.readFile process.argv[2], defer err, res
res = strip res.toString()
b = new Buffer res, 'hex'
[err, obj] = bdecode b
console.log err
console.log util.inspect obj, null, { depth : null}
