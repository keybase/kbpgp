
fs = require 'fs'
purepack = require 'purepack'
util = require 'util'

strip = (x) ->
  v = x.split /\s+/
  v.join ''

await fs.readFile process.argv[2], defer err, res
res = strip res.toString()
b = new Buffer res, 'hex'
[err, obj] = purepack.unpack b, 'buffer'
console.log util.inspect obj, null, { depth : null}
