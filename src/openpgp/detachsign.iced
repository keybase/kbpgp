#
# Detachsign ---
#
#    Like burner.iced, but for detach-signing only.
# 
#==========================================================================================


{make_esc} = require 'iced-error'
tsec = require 'triplesec'
{SHA512} = tsec.hash
{WordArray} = require tsec
{Signature,CreationTime,Issuer} = require './packet/signature'
{unix_time} = require '../util'
triplesec = require 'triplesec'
{WordArray} = triplesec
konst = require '../const'
C = konst.openpgp
Ch = require '../header'
{SHA512} = triplesec.hash
{encode} = require './armor'
{Literal} = require "./packet/literal"

#====================================================================

hash_obj_to_fn = (obj) -> (buf) -> obj.finalize(WordArray.from_buffer(buf)).to_buffer()

#====================================================================

class Signer 

  #---------------------------------------------------

  constructor : ({@data, @hash_obj, @signing_key}) ->

  #---------------------------------------------------

  run : (cb) ->
    esc = make_esc cb, "Signer::run"
    await @_run_hash esc defer()
    await @_sign esc signature
    await @_encode esc defer encoded
    cb null, signature, encoded

  #---------------------------------------------------

  scrub : () ->

  #---------------------------------------------------

  _sign : (cb) ->

    @sig = new Signature {
      sig_type : C.sig_types.canonical_text,
      key : @signing_key.key,
      hashed_subpackets : [ new CreationTime(unix_time()) ],
      unhashed_subpackets : [ new Issuer @signing_key.get_key_id() ],
      hasher : hash_obj_to_fn(@hash_obj)
    }
    emptybuf = new Buffer []
    await @sig.write emptybuf, defer err, @_sig_output
    cb err

  #---------------------------------------------------

  _encode : (cb) ->
    ret = encode C.message_types.signature, @_sig_output
    cb err, ret

  #---------------------------------------------------

  _run_hash : (cb) ->
    err = null
    if @hash_obj? then # noop
    else if @data?
      @hash_obj= new SHA512()
      @hash_obj.update WordArray.from_buffer @data
    else
      err = new Error "Need either a hasher or data"
    cb err

#====================================================================

class Verifier

  #-----------------------

  constructor : ({@packets, @data, @data_fn, @key_fetch}) ->

  #-----------------------

  _find_signature : (cb) ->
    err = if (n = @packets.length) isnt 1 
      new Error "Expected one signature packet; got #{n}"
    else if (@_sig = @packets[0]).tag isnt C.packet_tags.signature 
      new Error "Expected a signature packet; but got type=#{@packets[0].tag}"
    else
      null
    cb null

  #-----------------------

  _consume_data : (cb) ->
    err = null
    klass = @_sig.hasher.klass
    hasher = new klass()
    if @data then hasher.update WordArray.from_buffer @data
    else
      go = true
      while go
        await @data_fn hasher, defer err, done
        go = false if err or done
    @_sig.hasher = hash_obj_to_fn hasher 
    cb err

  #-----------------------

  run : (cb) ->
    esc = make_esc cb, "Verifier::run"
    await @_find_signature esc defer()
    await @_consume_data esc defer()
    await @_verify esc defer()
    cb null

#====================================================================

exports.sign = ({data, hash_obj, signing_key}, cb) ->
  s = new Signer { data, hash_obj, signing_key }
  await s.run defer err, encoded, signature
  s.scrub()
  cb err, encoded, signature

#====================================================================

exports.verify = ({data, data_fn, packets, key_fetch}, cb) ->
  v = new Verifier { data, data_fn, hasher, packets, key_fetch }
  await v.run defer err
  cb err

#====================================================================

