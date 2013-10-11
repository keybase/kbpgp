
openpgp = require 'openpgp'
openpgp.openpgp.init()
fs = require 'fs'

#await fs.readFile "./x", defer err, res
#s = res.toString 'binary'
#console.log openpgp.packet.packet.read_packet s, 0, s.length

await fs.readFile "./y", defer err, res
s = res.toString 'utf8'
console.log openpgp.openpgp.read_privateKey s
