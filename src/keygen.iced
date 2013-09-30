
{RSA} = require './rsa'
triplesec = require 'triplesec'
{util,openpgp,packet,msg,encoding} = require 'openpgp'
{ASP,uint_to_buffer,make_time_packet} = require './util'
C = require('./const').openpgp
{make_esc} = require 'iced-error'
{UserID} = require './packet/userid'
openpgpkm = require './packet/keymaterial'
kbkm = require './kbpacket/keymaterial'
{encode} = require './encode/armor'

#=================================================================

class KeyFactory

  #=================================================================

  #
  # Generate a new raw keypair, and then perform some higher-level
  # finessing, like generating a self-signature for this key, and armoring
  # the public-key pair for export to the user.
  #
  # @param {number} nbits The number of bits in the keypair, taken to be 4096 by default.
  # @param {string} userid The userid that's going to be written into the key.
  # @param {number} delay The number of msec to wait between each iter of the inner loop
  # @param {callback} cb Call with an `(err,res)` pair when we are done. res
  #   will have to subobjects: `publicKeyArmored` and `privateKeyObject`.
  #   The `privateKeyObject` has three fields: a `signature` of type {Buffer},
  #   a `userid` of type {String}, and a `privateKey` of type {Buffer}.  This
  #   last field should be TripleSec'ed before being written anywhere.
  # @return {Canceler} A canceler object you can call cancel() on if you want
  #   to give up on this.
  generate_keypair : ({nbits, userid, progress_hook, delay}, cb) ->
    asp = new ASP { progress_hook, delay }
    @_generate_keypair { nbits, userid, asp }, cb
    return asp.canceler()

  #--------

  #
  # Follows generate_key_pair from src/openpgp.js
  #
  # @param {ASP} asp standard ASyncPackage to pass into the key
  #   generation algorithm.
  _generate_keypair : ({nbits, asp, userid, passphrase}, cb) ->
    uid = new UserID userid
    uidb = uid.userid

    esc = make_esc cb, "KeyFactor::_generate_keypair"

    await RSA.generate { nbits, asp }, esc defer key

    # When this case was generated
    now = Date.now()

    # Generate a KeyMaterial chain for OpenPGP-style
    o = new openpgpkm.KeyMaterial key, { now, uid, passphrase }
    k = new kbkm.KeyMaterial key, { now, uid, passphrase }
    ret = {}
    await 
      o.export_keys esc defer ret.openpgp
      k.export_keys esc defer ret.keybase
    cb null, ret

  #--------


    await @self_sign_key key_packet, uidb, esc defer sig

    openpgp = @_output_openpgp { key_packet, uid, sig }
    kb = @_output_keybase { key_packet, uid, sig }



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

  #---------------------------------


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
  await generate_keypair { nbits : 1024, progress_hook, userid : "Max Krohn <max@keybase.io>"}, defer err, key
  console.log key
  process.exit 0

#=================================================================

exports.generate_keypair = generate_keypair
exports.generate_raw_keypair = generate_raw_keypair

#=================================================================

