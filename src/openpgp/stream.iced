
{BaseBurner} = require './baseburner'
hashmod = require '../hash'
C = require('../const').openpgp
{unix_time} = require '../util'
{Literal} = require './packet/literal'
stream = require 'stream'
{make_esc} = require 'iced-error'

#===========================================================================

class Pipeline extends stream.Transform

  constructor : () ->
    @xforms = []
    @last = null
    super()

  push_xform : (x) ->
    @last.pipe(x) if @last?
    @xforms.push x
    @last = x

  start : () ->
    @last.on 'data', (chunk) -> @push chunk
    @last.on 'emit', (err) -> @emit 'error', err

  _transform : (chunk, encoding, cb) ->
    await @xforms[0].write chunk, encoding, defer()
    cb()

  _flush : (cb) ->
    for x in @xforms
      await x.end defer()
    cb()

#===========================================================================

class BoxTransformEngine extends BaseBurner

  #--------------------------------

  constructor : ({@opts, sign_with, encrypt_for, signing_key, encryption_key}) -> 
    super { sign_with, encrypt_for, signing_key, encryption_key }
    @packets = []
    @pipeline = new Pipeline

  #--------------------------------

  _read_opts : (cb) ->
    err = null

    v = @opts?.compression or 'none'
    if not (@compression = C.compression[v])? then err = new Error "no known compression: #{v}"
    v = @opts?.encoding or 'binary'
    if not (@encoding = C.literal_formats[v])? then err = new Error "no known encoding: #{v}"

    cb err

  #--------------------------------

  init : (cb) ->
    esc = make_esc cb, "Burner::init"
    await @_find_keys esc defer()
    await @_read_opts esc defer()

    literal = new Literal { format : @encoding, date : unix_time() }

    if @signing_key?
      @pipeline.push @_make_ops_packet().new_stream { sig: @_make_sig_packet(), literal }
    else
      @pipeline.push literal.new_stream()

    #if @compression isnt C.compression.none
    #  @pipeline.push new CompressionTransform algo
    #if @encryption_key?
    #  await @_setup_encryption esc defer()
    #  @pipeline.push new EncryptionTransform { pkesk : @_pkesk, cipher : @_cipher}

    @pipeline.start()
    cb null, @pipeline

#===========================================================================

exports.box = (opts, cb) ->
  eng = new BoxTransformEngine opts
  await eng.init defer err, xform
  cb err, xform

#===========================================================================

#input = fs.createReadStream "bigfile"
#out = fs.createWriteStream "outfile"
#await input.once 'error', esc defer()
#await kb.stream.box { sign_with, encrypt_for }, esc defer xform
#input.pipe(xform).pipe(output)
#await input.once 'eof', esc defer()