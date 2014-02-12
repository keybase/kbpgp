#
# Clearsign ---
#
#    Like burner.iced, but for clear-signing only.
# 
#==========================================================================================

{make_esc} = require 'iced-error'
{Signature,CreationTime,Issuer} = require './packet/signature'
{unix_time} = require '../util'
{SRF} = require '../rand'
triplesec = require 'triplesec'
{export_key_pgp,get_cipher} = require '../symmetric'
{scrub_buffer} = triplesec.util
{WordArray} = triplesec
C = require('../const').openpgp
{SHA512} = require '../hash'
{encode} = require './armor'
{clearsign_header} = require('pgp-utils').armor

#==========================================================================================

class ClearSigner

  #------------

  # @param {Buffer} msg the message to clear sign
  # @param {openpgp.packet.KeyMaterial} signing_key the key to find
  constructor : ({@msg, @signing_key}) ->
    @packets = []

  #------------

  _fix_msg : (cb) ->
    m = @msg.toString('utf8')
    parts = m.split /\n\r?/
    unless parts[-1...][0] is ''
      parts.push ''
      @msg += "\n"
    txt = parts.join("\n\r")
    @fixed_msg = new Buffer txt, 'utf8'
    cb null

  #------------

  _sign_msg : (cb) ->
    @sig = new Signature {
      sig_type : C.sig_types.canonical_text
      key : @signing_key.key
      hashed_subpackets : [ new CreationTime(unix_time()) ]
      unhashed_subpackets : [ new Issuer @signing_key.get_key_id() ]
    }
    await @sig.write @fixed_msg, defer err, fp
    @packets.push fp unless err?
    cb err

  #------------

  scrub : () ->

  #------------

  hasher_name : () -> @sig.hasher.algname

  #------------

  run : (cb) ->
    esc = make_esc cb, "ClearSigner::run"
    await @_fix_msg esc defer()
    await @_sign_msg esc defer()
    output = Buffer.concat @packets
    cb null, output

#==========================================================================================

# @param {Buffer} msg the message to clear sign
# @param {openpgp.packet.KeyMaterial} signing_key the key to find
# @param {Callback<error,String,Buffer>} cb with the error (if there was one)
#    the string of the PGP message, and finally the raw signature.
exports.clearsign = ({msg, signing_key}, cb) ->
  b = new ClearSigner { msg, signing_key }
  await b.run defer err, raw
  if not err? and raw?
    hdr = clearsign_header C, b.msg, b.hasher_name()
    body = encode(C.message_types.signature, raw)
  cb err, (hdr + body), raw

#==========================================================================================
