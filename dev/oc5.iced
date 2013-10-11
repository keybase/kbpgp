
{openpgp} = require('openpgp')
openpgp.init()
fs = require 'fs'
await fs.readFile '../xa', defer err, buffer
pk = openpgp.read_privateKey buffer.toString 'utf8'
console.log pk
pk[0].decryptSecretMPIs 'asdfqwer'
console.log pk[0]
for i in pk[0].privateKeyPacket.secMPIs
  console.log i.toString()

#packet = new KeyMaterial()
#packet.IV = (new Buffer "b61522b832d04bfd", "hex").toString 'binary'
#packet.IVLength = packet.IV.length