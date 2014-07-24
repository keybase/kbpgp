
{BaseBurner} = require './baseburner'
hashmod = require '../hash'
C = require('../const').openpgp
{unix_time} = require '../util'
{Literal} = require './packet/literal'
stream = require 'stream'
{make_esc} = require 'iced-error'
xbt = require '../xbt'
{Compressed} = require './packet/compressed'
{SEIPD} = require './packet/sess'
{DemuxSequence} = require './parser'
{XbtDearmorDemux,XbtArmorer} = require './armor'

#===========================================================================

class BoxTransformEngine extends BaseBurner

  #--------------------------------

  constructor : ({@opts, sign_with, encrypt_for, signing_key, encryption_key}) -> 
    super { sign_with, encrypt_for, signing_key, encryption_key }
    @packets = []

    @chain = new xbt.Chain
    @stream = new xbt.StreamAdapter { xbt: @chain }

  #--------------------------------

  can_pass_through : () -> true

  #--------------------------------

  _read_opts : (cb) ->
    err = null

    v = @opts?.compression or 'none'
    if not (@compression = C.compression[v])? then err = new Error "no known compression: #{v}"
    v = @opts?.encoding or 'binary'
    if not (@encoding = C.literal_formats[v])? then err = new Error "no known encoding: #{v}"

    # PGP armoring 
    if (v = @opts?.armor) and not (@armor = C.message_types[v])? 
      err = new Error "bad armor message type: #{v}"
      
    cb err

  #--------------------------------

  init : (cb) ->
    esc = make_esc cb, "Burner::init"
    await @_find_keys esc defer()
    await @_read_opts esc defer()

    literal = new Literal { format : @encoding, date : unix_time() }

    if @signing_key?
      sig = @_make_sig_packet { hasher : hashmod.streamers.SHA512() }
      @chain.push_xbt @_make_ops_packet().new_xbt { sig, literal }
    else
      @chain.push_xbt literal.new_xbt()

    if @compression isnt C.compression.none
      @chain.push_xbt (new Compressed { algo : @compression}).new_xbt()

    if @encryption_key?
      await @_setup_encryption esc defer()
      @chain.push_xbt (new SEIPD {}).new_xbt { @pkesk, @cipher, @prefixrandom }

    if @armor?
      @chain.push_xbt new XbtArmorer { type : @armor }

    cb null, @stream

#===========================================================================

class UnboxTransformEngine

  #---------------------------------------

  constructor : ({@xbt_opts, @keyfetch}) ->
    @chain = new xbt.Chain 
    @stream = new xbt.StreamAdapter { xbt : @chain }

  #---------------------------------------

  init : (cb) ->
    @chain.push_xbt(new XbtDearmorDemux {}).push_xbt(new DemuxSequence {})
    cb null, @stream

#===========================================================================

exports.box = (opts, cb) ->
  eng = new BoxTransformEngine opts
  await eng.init defer err, xform
  cb err, xform

#===========================================================================

exports.unbox = (opts, cb) ->
  eng = new UnboxTransformEngine opts
  await eng.init defer err, xform
  cb err, xform, eng

#===========================================================================
