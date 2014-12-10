#
# Detachsign ---
#
#    Like burner.iced, but for detach-signing only.
# 
#==========================================================================================


{make_esc} = require 'iced-error'
{Signature,CreationTime,Issuer} = require './packet/signature'
{unix_time} = require '../util'
{WordArray} = require 'triplesec'
konst = require '../const'
C = konst.openpgp
Ch = require '../header'
{streamers} = require '../hash'
{encode} = require './armor'
{Literal} = require "./packet/literal"
VerifierBase = require('./verifier').Base
packetsigs = require './packet/packetsigs'

#====================================================================

hash_obj_to_fn = (obj) -> 
  fn = (buf) -> obj.finalize(WordArray.from_buffer(buf)).to_buffer()
  fn.algname = buf.algname

#====================================================================

class Signer 

  #---------------------------------------------------

  constructor : ({@data, @hash_streamer, @signing_key}) ->

  #---------------------------------------------------

  run : (cb) ->
    esc = make_esc cb, "Signer::run"
    await @_run_hash esc defer()
    await @_sign esc defer signature
    await @_encode esc defer encoded
    cb null, encoded, signature

  #---------------------------------------------------

  scrub : () ->

  #---------------------------------------------------

  _sign : (cb) ->

    @sig = new Signature {
      sig_type : C.sig_types.canonical_text,
      key : @signing_key.key,
      hashed_subpackets : [ new CreationTime(unix_time()) ],
      unhashed_subpackets : [ new Issuer @signing_key.get_key_id() ],
      hasher : @hash_streamer
    }
    emptybuf = new Buffer []
    await @sig.write emptybuf, defer err, @_sig_output
    cb err, @_sig_output

  #---------------------------------------------------

  _encode : (cb) ->
    err = null
    ret = encode C.message_types.signature, @_sig_output
    cb err, ret

  #---------------------------------------------------

  _run_hash : (cb) ->
    err = null
    if @hash_streamer? then # noop
    else if @data?
      @hash_streamer = streamers.SHA512()
      @hash_streamer.update @data
    else
      err = new Error "Need either a hasher or data"
    cb err

#====================================================================

class Verifier extends VerifierBase

  #-----------------------

  constructor : ({packets, @data, @data_fn, keyfetch}) ->
    super { packets, keyfetch }

  #-----------------------

  _consume_data : (cb) ->
    err = null
    if @data_fn?
      err = null
      klass = @_sig.hasher.klass
      streamer = streamers[@_sig.hasher.algname]()
      buf_hasher = (buf) -> streamer.update buf
      go = true
      while go
        await @data_fn buf_hasher, defer err, done
        go = false if err? or done
      @_sig.hasher = streamer
    cb err

  #-----------------------

  _verify : (cb) ->
    data = if @data then [ new Literal  { @data } ]
    else []
    @literals = data
    await @_sig.verify data, defer err
    cb err

  #-----------------------

  _make_literals : (cb) ->
    unless @literals.length
      @literals.push new Literal { data : new Buffer [] } 
    @literals[0].push_sig new packetsigs.Data { sig : @_sig }
    cb null

  #-----------------------

  run : (cb) ->
    esc = make_esc cb, "Verifier::run"
    await @_find_signature esc defer()
    await @_fetch_key esc defer()
    await @_consume_data esc defer()
    await @_verify esc defer()
    await @_make_literals esc defer()
    cb null, @literals

#====================================================================

exports.sign = ({data, hash_streamer, signing_key}, cb) ->
  s = new Signer { data, hash_streamer, signing_key }
  await s.run defer err, encoded, signature
  s.scrub()
  cb err, encoded, signature

#====================================================================

exports.verify = ({data, data_fn, packets, keyfetch}, cb) ->
  v = new Verifier { data, data_fn, packets, keyfetch }
  await v.run defer err, literals
  cb err, literals

#====================================================================

