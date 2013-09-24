
{generate_rsa_keypair} = require './rsa'
triplesec = require 'triplesec'
{packet} = require 'openpgp'
{make_time_packet} = require './util'
enum = require './enum'

#=================================================================

# 
# Generate a new keypair.  I only generate RSA keys, so you don't
# have an option.  If passphrase is provided, then we'll be triple-secing
# the output private key.  If not, then we'll return it in the clear.
# At no point will we be using OpenPGP's decryption, but we can
# in the future.

generate_key = ({nbits, progress_hook, passphrase}, cb)  ->
  nbits or= 4096
  d = Date.now()/1000
  b = new Buffer 4
  await generate_rsa_keypair { nbits, iters : 10, progress_hook }, defer key
  type = enum.openpgp.public_key_algorithms.RSA
  pub = (new packet.KeyMaterial()).write_public_key type, key, timePacket
  priv = (new packet.KeyMaterial()).write_private_key type, key, null, null, null, timePacket
  ret = { privateKey : priv, publicKey : pub }
  cb ret

#=================================================================

progress_hook = (obj) ->
  if obj.p?
    s = obj.p.toString()
    s = "#{s[0...3]}....#{s[(s.length-6)...]}"
  else
    s = ""
  interval = if obj.total? and obj.i? then "(#{obj.i} of #{obj.total})" else ""
  console.log "+ #{obj.what} #{interval} #{s}"
await generate_key { nbits : 2048, progress_hook }, defer key
console.key key
process.exit 0