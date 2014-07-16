
# Burner ----
#
#   A series of libraries for making your own OpenPGP messages.  Will do things
#   like signatures and encryptions.
# 

#==========================================================================================

{make_esc} = require 'iced-error'
{OnePassSignature} = require './packet/one_pass_sig'
{Signature,CreationTime,Issuer} = require './packet/signature'
{Compressed} = require './packet/compressed'
{Literal} = require './packet/literal'
{unix_time} = require '../util'
{SRF} = require '../rand'
triplesec = require 'triplesec'
{export_key_pgp,get_cipher} = require '../symmetric'
{scrub_buffer} = triplesec.util
{WordArray} = triplesec
{SEIPD,PKESK} = require './packet/sess'
C = require('../const').openpgp
{SHA512} = require '../hash'
{encode} = require './armor'
clearsign = require './clearsign'
detachsign = require './detachsign'
{BaseBurner} = require './baseburner'

#==========================================================================================

dummy_key_id = new Buffer( 0 for [0...16] ) 

#==========================================================================================

class Burner extends BaseBurner

  #------------

  constructor : ({@literals, @opts, sign_with, encrypt_for, signing_key, encryption_key}) ->
    super { sign_with, encrypt_for, signing_key, encryption_key }
    @opts or= {}
    @signed_payload = null

  #------------

  _frame_literals : (cb) ->
    esc = make_esc cb, "Burner::_frame_literals"
    sp = []
    for l in @literals
      sp.push l.to_signature_payload()
      await l.write esc defer p
      @packets.push p
    @signed_payload = Buffer.concat sp
    cb null

  #------------

  _sign : (cb) ->
    esc = make_esc cb, "Burner::_sign'"
    await @_make_ops_packet().write esc defer ops_framed
    @packets.unshift ops_framed
    await @_make_sig_packet({}).write @signed_payload, esc defer fp
    @packets.push fp
    cb null
    
  #------------

  collect_packets : () ->
    ret = Buffer.concat @packets
    @packets = []
    ret

  #------------

  _compress : (cb) ->
    inflated = @collect_packets()
    pkt = new Compressed { algo : C.compression.zlib, inflated }
    await pkt.write defer err, opkt
    unless err?
      @packets.push opkt
    cb err

  #------------

  scrub : () ->
    @_cipher.scrub() if @_cipher?
    scrub_buffer @_session_key if @_session_key?

  #------------

  _encrypt_payload : (cb) ->
    esc = make_esc cb, "Burner::_encrypt_payload"
    plaintext = @collect_packets()
    await SRF().random_bytes @_cipher.blockSize, defer prefixrandom
    pkt = new SEIPD {}
    await pkt.encrypt { cipher : @_cipher, plaintext, prefixrandom }, esc defer()
    await pkt.write esc defer pkt
    scrub_buffer plaintext
    @packets = [ @_pkesk, pkt ]
    cb null

  #------------

  _encrypt : (cb) ->
    esc = make_esc cb, "Burner::_encrypt"
    await @_setup_encryption esc defer()
    await @_encrypt_payload esc defer()
    cb null

  #------------

  scrub : () ->

  #------------
  
  burn : (cb) ->
    esc = make_esc cb, "Burner::burn"
    await @_find_keys esc defer()
    await @_frame_literals esc defer()
    if @signing_key
      await @_sign esc defer()
    await @_compress esc defer()
    if @encryption_key
      await @_encrypt esc defer()
    output = Buffer.concat @packets
    cb null, output

#==========================================================================================

exports.Burner = Burner

#==========================================================================================

exports.make_simple_literals = make_simple_literals = (msg) ->
  return [ new Literal { 
    data : new Buffer(msg)
    format : C.literal_formats.utf8 
    date : unix_time()
  }]

#==========================================================================================

exports.clearsign = clearsign.sign
exports.detachsign = detachsign.sign

#==========================================================================================

#
# burn
#
#   Hi-level interface to 'burning' a new GPG message.  Not well-named.
#   Should probably be renamed to "box"ing a message, or something similar.
#   Anyways, think of it as burning a CD-ROM in 1999, which is basically when
#   the PGP protocol is from.
#
#   Can specify messages as Utf8 strings, raw buffers, or an array of Literal
#   open-PGP packets.
#
#   Can specify a signing_key OR sign_with if you want the message signed.
# 
#   Can specify an encryption_key OR encrypt_for if you want the message encrypted.
#
# @param {String || Buffer} msg the payload, which will be made into literals
# @param {Array<openpgp.packets.Literal>} literals the literal packets that make up the payload.
#
# @param {KeyManager} encrypt_for Who to encrypt for (optional)
# @param {KeyManager} sign_by Who will sign it (optional)
# @param {openpgp.packets.KeyMaterial} signing_key the key to sign with 
# @param {openpgp.packets.KeyMaterial} encryption_key the key to encrypt with 
#
# @param {Object} opts Various options to pass through.  So far:
#          - hide --- include a dummy key in the packet, to protect the identity of the
#                      recipient.
#          - hide.max --- The maximum size of a key. 8192 for RSA by default. 4096 for ElGamal
#          - hide.slosh -- The amount of slosh over the max to introduce. 128 by default. In bits.
#
# @param {callback} cb Callback with an ({Error},{Bufffer},{Buffer}) triple.  Error is
#    set if there was an error, otherwise, we'll get back the PGP output in first armored
#    and then raw binary form.
#
exports.burn = ({msg, literals, sign_with, encrypt_for, signing_key, encryption_key, opts}, cb) ->
  literals = make_simple_literals msg if msg? and not literals?
  b = new Burner { literals, sign_with, encrypt_for, signing_key, encryption_key, opts }
  await b.burn defer err, raw
  b.scrub()
  aout = encode(C.message_types.generic, raw) if raw? and not err?
  cb err, aout, raw

#==========================================================================================
