
{generate_rsa_keypair} = require './rsa'
triplesec = require 'triplesec'
{util,openpgp,packet,msg,encoding} = require 'openpgp'
{uint_to_buffer,make_time_packet} = require './util'
C = require('./const').openpgp

#=================================================================

# 
# Generate a new raw keypair.  I only generate RSA keys, so you don't
# have an option.  If passphrase is provided, then we'll be triple-secing
# the output private key.  If not, then we'll return it in the clear.
# At this point will are not using OpenPGP's decryption, but we can
# in the future.
#
# A replacement for OpenPGP's openpgp_crypto_generateKeyPair
#
# @param {number} nbits The number of bits in the key (default is 4096)
# @param {function} progress_hook Called back to update the U/I what's going on.
# @param {callback} cb Callback with a raw keypair.
#
generate_raw_keypair = ({nbits, progress_hook}, cb)  ->
  nbits or= 4096
  timePacket = make_time_packet()
  await generate_rsa_keypair { nbits, iters : 10, progress_hook }, defer key
  type = C.public_key_algorithms.RSA
  pub = (new packet.KeyMaterial()).write_public_key type, key, timePacket
  priv = (new packet.KeyMaterial()).write_private_key type, key, null, null, null, timePacket
  ret = { privateKey : priv, publicKey : pub }
  cb ret

#=================================================================

#
# Generate a new raw keypair, and then perform some higher-level
# finessing, like generating a self-signature for this key, and armoring
# the public-key pair for export to the user.
#
# @param {number} nbits The number of bits in the keypair, taken to be 4096 by default.
# @param {function} progress_hook A standard progress hook to pass into the key
#   generation algorithm.
# @param {string} userid The userid that's going to be written into the key.
# @param {callback} cb Call with an `(err,res)` pair when we are done. res
#   will have to subobjects: `publicKeyArmored` and `privateKeyObject`.
#   The `privateKeyObject` has three fields: a `signature` of type {Buffer},
#   a `userid` of type {String}, and a `privateKey` of type {Buffer}.  This
#   last field should be TripleSec'ed before being written anywhere.
#
generate_keypair = ({nbits, progress_hook, userid}, cb) ->
  userIdString = (new packet.UserID()).write_packet(userid);
  await generate_raw_key { nbits, progress_hook }, defer key
  privKeyString = key.privateKey.string

  # The '3' is the offset to start reading from.  Please excuse this mess.
  privKeyPacket = (new packet.KeyMaterial()).read_priv_key(privKeyString,3,privKeyString.length)

  if not privKeyPacket.decryptSecretMPIs()
    err = new Error 'failed to read unencrypted secret key data'
    ret = null
  else
    err = null
    privKey = new msg.PrivateKey()
    privKey.privateKeyPacket = privKeyPacket
    privKey.getPreferredSignatureHashAlgorithm = () -> C.hash_algorithms.SHA512

    publicKeyString = privKey.privateKeyPacket.publicKey.data
    userid_buffer = new Buffer userid, 'utf8'

    bufs = [
      new Buffer [ 0x99 ],
      uint_to_buffer(16, publicKeyString.length),
      new Buffer(publicKeyString, 'binary'),
      new Buffer [ 0xb4 ],
      uint_to_buffer(32, userid_buffer.length),
      userid_buffer
    ]
    hashData = Buffer.concat(bufs).toString('binary')
    signature = (new packet.Signature()).write_message_signature(C.subpacket_types.issuer, hashData, privKey)
    payload = (which) -> which + userIdString + signature.openpgp

    # We're not using this feature for now.... 
    # privateKeyArmored = encoding.armor C.message_types.private_key, payload(privKeyString)

    ret = 
      publicKeyArmored : encoding.armor C.message_types.public_key, payload(key.publicKey.string)
      privateKeyObject :
        signature : new Buffer signature.openpgp, 'binary'
        userid : userid
        privateKey : new Buffer privKeyString, 'binary'

  cb err, ret

#=================================================================

test = () ->
  progress_hook = (obj) ->
    if obj.p?
      s = obj.p.toString()
      s = "#{s[0...3]}....#{s[(s.length-6)...]}"
    else
      s = ""
    interval = if obj.total? and obj.i? then "(#{obj.i} of #{obj.total})" else ""
    console.log "+ #{obj.what} #{interval} #{s}"
  openpgp.init()
  await generate_key { nbits : 2048, progress_hook, userid : "Max Krohn <max@keybase.io>"}, defer err, key
  console.log key
  process.exit 0

#=================================================================

exports.generate_keypair = generate_keypair
exports.generate_raw_keypair = generate_raw_keypair

#=================================================================

