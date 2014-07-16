
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
    @__xforms = []
    @__last = null
    super()

  xform : (x) ->
    @__last.pipe(x) if @__last?
    @__xforms.push x
    @__last = x

  start : () ->
    i = 0
    @__last.on 'data', (chunk) -> 
      console.log "ok, chunked out.."
      console.log chunk
      await setTimeout defer(), 0
      console.log "nothing doing here... after sleep...."
      @push chunk
    @__last.on 'emit', (err) -> @emit 'error', err

  _transform : (chunk, encoding, cb) ->
    console.log "transform chunk.."
    console.log chunk
    await @__xforms[0].write chunk, encoding, defer()
    cb()

  _flush : (cb) ->
    console.log "flushing it!"
    for x in @__xforms
      console.log "ok, in flush situation..."
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
      @pipeline.xform @_make_ops_packet().new_stream { sig: @_make_sig_packet(), literal }
    else
      @pipeline.xform literal.new_stream()

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

class SimpleXform extends stream.Transform

  _transform : (chunk, encoding, cb) ->
    console.log "push in simple"
    console.log chunk
    @push chunk
    console.log "pushed!"
    cb()

#input = fs.createReadStream "bigfile"
#out = fs.createWriteStream "outfile"
#await input.once 'error', esc defer()
#await kb.stream.box { sign_with, encrypt_for }, esc defer xform
#input.pipe(xform).pipe(output)
#await input.once 'eof', esc defer()


x = new Pipeline()
x.xform new SimpleXform()
x.start()
buf = new Buffer "helloo what the fuck man"
await x.write buf, defer()
x.on 'data', (data) ->
  console.log "got data"
  console.log data.toString 'utf8'
await x.end defer()
console.log "done"