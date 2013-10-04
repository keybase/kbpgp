{RSA} = require './rsa'
triplesec = require 'triplesec'
{util,openpgp,packet,msg,encoding} = require 'openpgp'
{bufferify,unix_time,ASP,uint_to_buffer,make_time_packet} = require './util'
C = require('./const').openpgp
{prng} = triplesec
{make_esc} = require 'iced-error'
{UserID} = require './packet/userid'
openpgpkm = require './packet/keymaterial'
kbkm = require './kbpacket/keymaterial'
{encode} = require './encode/armor'
{base91} = require './basex'

#=================================================================

#=================================================================

#
# Generate a new raw keypair, and then perform some higher-level
# finessing, like generating a self-signature for this key, and armoring
# the public-key pair for export to the user.
#
# @param {number} nbits The number of bits in the keypair, taken to be 4096 by default.
# @param {string} userid The userid that's going to be written into the key.
# @param {number} delay The number of msec to wait between each iter of the inner loop
# @param {string} passphrase The passphrase to encrypt everything with
# @param {callback} cb Call with an `(err,res)` pair when we are done. res
#   will have to subobjects: `publicKeyArmored` and `privateKeyObject`.
#   The `privateKeyObject` has three fields: a `signature` of type {Buffer},
#   a `userid` of type {String}, and a `privateKey` of type {Buffer}.  This
#   last field should be TripleSec'ed before being written anywhere.
# @return {Canceler} A canceler object you can call cancel() on if you want
#   to give up on this.
generate_keypair = ({nbits, userid, progress_hook, delay, passphrase}, cb) ->
  asp = new ASP { progress_hook, delay }
  _generate_keypair { nbits, userid, asp, passphrase }, cb
  return asp.canceler()

#--------

#
# Follows generate_key_pair from src/openpgp.js
#
# @param {ASP} asp standard ASyncPackage to pass into the key
#   generation algorithm.G
_generate_keypair = ({nbits, asp, userid, passphrase}, cb) ->
  userid = bufferify userid
  passphrase = bufferify passphrase

  esc = make_esc cb, "KeyFactor::_generate_keypair"
  await RSA.generate { nbits, asp }, esc defer key

  # Make a random password for OpenPGP for now
  await prng.generate 11, defer rd
  pp_openpgp = base91.encode rd.to_buffer()
  pp_openpgp_buf = new Buffer pp_openpgp, 'utf8'

  # When this case was generated
  timestamp = unix_time()

  # Generate a KeyMaterial chain for OpenPGP-style
  o = new openpgpkm.KeyMaterial { key, timestamp, userid, passphrase : pp_openpgp_buf  }
  k = new kbkm.KeyMaterial { key, timestamp, userid, passphrase }
  ret = {}
  await o.export_keys {}, esc defer ret.openpgp
  await k.export_keys { progress_hook: asp.progress_hook() }, esc defer ret.keybase
  ret.openpgp.passphrase = pp_openpgp
  cb null, ret

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
    console.warn "+ #{obj.what} #{interval} #{s}"
  await generate_keypair { nbits : 2048, userid : new Buffer('Rerl'), progress_hook, passphrase : new Buffer("asdfqwer") }, defer err, res
  console.log res
  console.log res.openpgp.private
  console.log res.openpgp.public
  console.log res.keybase.private.toString 'hex'
  console.log res.openpgp.passphrase
  process.exit 0
  openpgp.init()
  await generate_keypair { nbits : 4096, progress_hook, userid : "Max Krohn <max@keybase.io>", passphrase : "ejjejjee"}, defer err, key
  console.log key
#test()

#=================================================================

exports.generate_keypair = generate_keypair

#=================================================================


