
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

#==========================================================================================

class Burner

  #------------

  constructor : ({@literals, @signing_key, @encryption_key}) ->
    @packets = []
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
    await sig.write @signed_payload, defer err, fp
    unless err?
      @packets.unshift ops_framed
      @packets.push fp
    cb err
    
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

  _encrypt_session_key : (cb) ->
    payload = export_key_pgp @_cipher_algo, @_session_key
    k = @encryption_key.key
    await k.pad_and_encrypt payload, defer err, ekey
    unless err?
      pkt = new PKESK { 
        crypto_type : k.type,
        key_id : @encryption_key.get_key_id(),
        ekey : ekey
      } 
      await pkt.write defer err, @_pkesk
    cb err

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
    await @_make_session_key esc defer()
    await @_encrypt_session_key esc defer()
    await @_encrypt_payload esc defer()
    cb null

  #------------

  scrub : () ->

  #------------
  
  burn : (cb) ->
    esc = make_esc cb, "Burner::burn"
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

#==========================================================================================

exports.burn = ({msg, literals, signing_key, encryption_key}, cb) ->
  literals = make_simple_literals msg if msg? and not literals?
  b = new Burner { literals, signing_key, encryption_key }
  await b.burn defer err, raw
  b.scrub()
  aout = encode(C.message_types.generic, raw) if raw? and not err?
  cb err, aout, raw

#==========================================================================================
