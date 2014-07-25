
{BaseBurner} = require './baseburner'
hashmod = require '../hash'
konst = require '../const'
C = konst.openpgp
{athrow,bufeq_secure,unix_time} = require '../util'
{Literal} = require './packet/literal'
stream = require 'stream'
{make_esc} = require 'iced-error'
xbt = require '../xbt'
{Compressed} = require './packet/compressed'
{SEIPD} = require './packet/sess'
{Demux} = require './parser'
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

  constructor : ({@keyfetch}) ->
    @chain = new xbt.Chain
    @stream = new xbt.StreamAdapter { xbt : @chain }

  #---------------------------------------

  init : (cb) ->
    @chain.verify_sig = @verify_sig.bind(@)
    @chain.push_xbt(new XbtDearmorDemux {}).push_xbt(new Demux {})
    cb null, @stream

  #---------------------------------------

  verify_sig : (cb) ->
    esc = make_esc cb , "UnboxTransformEngine::verify_sig"
    {ops,sig} = @chain.get_metadata()

    if not ops? or not sig?
      err = new Error "Can only verify a OnePassSig/Signature configuration in streaming mode"
    else if not (hasher = @chain.pop_hasher())?
      err = new Error "No running hasher going, can't proceed"
    else if (a = hasher.type) isnt (b = sig.hasher.type)
      err = new Error "Hasher type mismatch: #{a} != #{b}"
    else if not bufeq_secure (a = ops.key_id), (b = sig.get_key_id())
      err = new Error "Key mismatch: #{a?.toString('hex')} v #{b?.toString('hex')}"
    else if not @keyfetch
      err = new Error "Cannot verify a signature without a keyfetch"

    await athrow err, esc defer() if err?

    await @keyfetch.fetch [a], konst.ops.verify, esc defer key_material, i, obj
    sig.key = key_material.key
    sig.keyfetch_obj = obj
    sig.hasher = hasher

    await sig.verify [], esc defer()
    sig.verified = true

    cb null

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
