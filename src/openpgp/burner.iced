
# Burner ----
#
#   A series of libraries for making your own OpenPGP messages.  Will do things
#   like signatures and encryptions.
# 

#==========================================================================================

{make_esc} = require 'iced-error'
{OnePassSignature} = require './packets/one_pass_sig'
{Signature,CreationTime,Issuer} = require './packets/signature'

#==========================================================================================

class Burner

  #------------

  constructor : ({literals, @signing_key, @encryption_key}) ->
    @_packets = literals

  #------------

  _sign : (cb) ->
    ops = new OnePassSignature { 
      sig_type : C.sig_types.binary_doc,
      hasher : SHA512
      sig_klass : @signing_key.get_klass()
      key_id : @signing_key.get_key_id()
      is_final : 1
    }
    @_packets.unshift ops
    sig = new Signature {
      type : C.sig_types.binary_doc
      key : @signing_key
      hashed_subpackets : [ new CreationTime(unix_time()) ]
      unhashed_subpackets : [ new Issuer @signing_key.get_key_id() ]
    }
    await sig.write_unframed @_packets, defer err, sig
    unless err?
      @_packets.push sig
    cb err
    
  #------------

  _encrypt : (cb) ->
    esc = make_esc cb, "Burner::_encrypt"
    await @_make_session_key esc defer()
    await @_encrypt_session_key esc defer()
    await @_encrypt_payload esc defer()
    cb null

  #------------
  
  burn : (cb) ->
    esc = make_esc cb, "Burner::burn"
    await @_frame_literal esc defer()
    if @signing_key
      await @_sign esc defer()
    await @_compress esc defer()
    if @encrypt_key
      await @_encrypt esc defer()
    await @_encode esc defer()
    cb null, @output

#==========================================================================================

exports.burn = ({msg, signing_key, encryption_key}, cb) ->
  b = new Burner { msg, signing_key, encryption_key }
  await b.burn defer err, out
  cb err, out

#==========================================================================================
