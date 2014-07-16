#
#
# XBT - eXplicit Buffer Transform
#
#    Transforms in which the buffering is explicit.  If you want to buffer,
#    it's up to you, but there's no buffering by default.
#   
#    You can use a StreamAdapter to turn one of these into a Node.js-style
#    stream
#
#=========================================================

stream = require 'stream'
{make_esc} = require 'iced-error'

#=========================================================

class Base

  constructor : () ->

  chunk : ({data, eof}, cb) -> cb new Error "unimplemented!"

#=========================================================

class Chain extends Base

  constructor : () ->
    @links = []

  push_xbt : (link) ->
    @links.push link

  chunk : ({data,eof}, cb) ->
    esc = make_esc cb, "Chain::chunk"
    out = null
    for l in @links
      await l.chunk {data,eof}, esc defer data
      out = data
    cb null, out

#=========================================================

class SimpleInit extends Base

  constructor : () ->
    @_did_init = false

  init : (cb) ->
    err = data = null
    unless @_did_init
      @_did_init = true
      await @_v_init defer err, data
    cb err, data

  chunk : ({data,eof}, cb) ->
    esc = make_esc cb, "SimpleInit::chunk"
    await @init esc defer init_data
    await @_v_chunk { data, eof }, esc defer out
    out = Buffer.concat([ init_data, out ]) if init_data?
    cb null, out

#=========================================================

class StreamAdapter extends stream.Transform

  constructor : ({@xbt}) ->
    super()

  _transform : (data, encoding, cb) ->
    if endcoding? then data = new Buffer data, encoding
    await @xbt.chunk { eof : false, data}, defer err, out
    @push(out) if not(err?) and out?
    cb err

  _flush : (cb) ->
    await @xbt.chunk { eof : true }, defer err, out
    @push(out) if not(err?) and out?
    cb err

#=========================================================

exports.Base = Base
exports.Chain = Chain
exports.SimpleInit = SimpleInit
exports.StreamAdapter = StreamAdapter

#=========================================================
