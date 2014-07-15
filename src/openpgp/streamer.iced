
{BaseBurner} = require './baseburner'
hashmod = require '../hash'
{PacketizerStream} = require './packet/packetizer_stream'

#===========================================================================

class Pipeline extends stream.Transform

  constructor : (@log2_packetsize) ->
    @log2_packetsize or= 16 # 64kB chunks by default
    @xforms = []
    @last = null
    super()

  push_xform : (x) ->
    last.pipe(x) if @last?
    ps = new PacketizerStream @log2_packetsize
    x.pipe(ps)
    @xforms.push x
    @xforms.push ps
    @last = ps

  start : () ->
    @last.on 'data', (chunk) -> @push chunk

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

  init : (cb) ->
    esc = make_esc cb, "Burner::init"
    await @_find_keys esc defer()
    if @signing_key
      @pipeline.push new SigningTransform @signing_key
    else
      @pipeline.push new LiteralTransform()
    if (algo = @opts.compress)
      @pipeline.push new CompressionTransform algo
    if @encryption_key
      await @_setup_encryption esc defer()
      @pipeline.push new EncryptionTransform { pkesk : @_pkesk, cipher : @_cipher}
    @pipeline.start()
    cb null, @pipeline

#===========================================================================

exports.box = (opts, cb) ->
  eng = new BoxTransformEngine opts
  await eng.init defer err, xform
  cb err, xform

#===========================================================================

input = fs.createReadStream "bigfile"
out = fs.createWriteStream "outfile"
await input.once 'error', esc defer()
await kb.stream.box { sign_with, encrypt_for }, esc defer xform
input.pipe(xform).pipe(output)
await input.once 'eof', esc defer()