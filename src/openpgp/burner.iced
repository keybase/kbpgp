
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

  constructor : ({@literals, @opts, sign_with, encrypt_for, signing_key, encryption_key, asp}) ->
    super { sign_with, encrypt_for, signing_key, encryption_key, asp }
    @packets = []
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
    ops = new OnePassSignature {
      sig_type : C.sig_types.binary_doc,
      hasher : SHA512
      sig_klass : @signing_key.get_klass()
      key_id : @signing_key.get_key_id()
      is_final : 1
    }
    await ops.write esc defer ops_framed
    sig = new Signature {
      type : C.sig_types.binary_doc
      key : @signing_key.key
      hashed_subpackets : [ new CreationTime(unix_time()) ]
      unhashed_subpackets : [ new Issuer @signing_key.get_key_id() ]
    }
    await @asp.progress { what : 'sign',  i : 0, total : 1 }, esc defer()
    await sig.write @signed_payload, esc defer fp
    await @asp.progress { what : 'sign',  i : 1, total : 1 }, esc defer()
    @packets.unshift ops_framed
    @packets.push fp
    cb null

  #------------

  collect_packets : () ->
    ret = Buffer.concat @packets
    @packets = []
    ret

  #------------

  _compress : (cb) ->
    esc = make_esc cb, "Burner::_compress"
    inflated = @collect_packets()
    pkt = new Compressed { algo : C.compression.zlib, inflated }
    await @asp.progress { what : 'compress', i : 0, total : 1 }, esc defer()
    await pkt.write esc defer opkt
    await @asp.progress { what : 'compress', i : 1, total : 1 }, esc defer()
    @packets.push opkt
    cb null

  #------------

  _make_session_key : (cb) ->
    @_cipher_algo = C.symmetric_key_algorithms.AES256
    @_cipher_info = get_cipher @_cipher_algo
    await SRF().random_bytes @_cipher_info.key_size, defer @_session_key
    @_cipher = new @_cipher_info.klass WordArray.from_buffer @_session_key
    cb null

  #------------

  scrub : () ->
    @_cipher.scrub() if @_cipher?
    scrub_buffer @_session_key if @_session_key?

  #------------

  _encrypt_session_key_once : (encryption_key, cb) ->
    esc = make_esc cb, "_encrypt_session_key_once"
    payload = export_key_pgp @_cipher_algo, @_session_key
    pub_k = encryption_key.key
    fingerprint = encryption_key.get_fingerprint()
    await @asp.progress { what : 'session key encrypt', i : 0, total : 1 }, esc defer()
    await pub_k.pad_and_encrypt payload, {fingerprint}, esc defer ekey
    await @asp.progress { what : 'session key encrypt', i : 1, total : 1 }, esc defer()
    if @opts.hide
      key_id = dummy_key_id
      await @asp.progress { what : 'hide encryption', i : 0, total : 1 }, esc defer()
      await ekey.hide { max : @opts.hide?.max, slosh : @opts.hide?.slosh, key : pub_k }, esc defer()
      await @asp.progress { what : 'hide encryption', i : 1, total : 1 }, esc defer()
    else
      key_id = encryption_key.get_key_id()
    pkt = new PKESK {
      crypto_type : pub_k.type,
      key_id : key_id,
      ekey : ekey
    }
    await pkt.write esc defer pkesk
    cb null, pkesk

  #------------

  _encrypt_session_key : (cb) ->
    esc = make_esc cb, "_encrypt_session_key"
    @_pkesks = []
    for k in @encryption_keys
      await @_encrypt_session_key_once k, esc defer pkesk
      @_pkesks.push pkesk
    cb null

  #------------

  _encrypt_payload : (cb) ->
    esc = make_esc cb, "Burner::_encrypt_payload"
    plaintext = @collect_packets()
    await SRF().random_bytes @_cipher.blockSize, defer prefixrandom
    pkt = new SEIPD {}
    asp = @asp.section 'encrypt payload'
    await pkt.encrypt { cipher : @_cipher, plaintext, prefixrandom, asp }, esc defer()
    await pkt.write esc defer pkt
    scrub_buffer plaintext
    @packets = @_pkesks.concat [pkt ]
    cb null

  #------------

  _encrypt : (cb) ->
    esc = make_esc cb, "Burner::_encrypt"
    await @_make_session_key esc defer()
    await @_encrypt_session_key esc defer()
    await @_encrypt_payload esc defer()
    cb null

  #------------

  scrub : () ->

  #------------

  burn : (cb) ->
    esc = make_esc cb, "Burner::burn"
    await @_find_keys esc defer()
    await @_frame_literals esc defer()
    if @signing_key?
      await @_sign esc defer()
    await @_compress esc defer()
    if @encryption_keys?
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
# @param {KeyManager} sign_with Who will sign it (optional)
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
exports.burn = ({msg, literals, sign_with, encrypt_for, signing_key, encryption_key, asp, opts}, cb) ->
  literals = make_simple_literals msg if msg? and not literals?
  b = new Burner { literals, sign_with, encrypt_for, signing_key, encryption_key, asp, opts }
  await b.burn defer err, raw
  b.scrub()
  aout = encode(C.message_types.generic, raw) if raw? and not err?
  cb err, aout, raw

#==========================================================================================
