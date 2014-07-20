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
assert = require 'assert'
{buf_indices_of,bufcat} = require './util'

#=========================================================

class Base

  constructor : () ->

  chunk : ({data, eof}, cb) -> cb new Error "unimplemented!"

#=========================================================

class Passthrough extends Base
  chunk : ({data, eof}, cb) -> cb null, data

#=========================================================

class Chain extends Base

  constructor : () ->
    @links = []

  push_xbt : (link) ->
    @links.push link
    @

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
    out = bufcat [ init_data, out ]
    cb null, out

#=========================================================

class InBlocker extends SimpleInit

  constructor : (@block_size) ->
    super()
    @_buffers = []
    @_dlen = 0
    @_p = 0
    @_input_len = 0

  #----------------------

  _push_data : (b) ->
    if b?.length
      @_buffers.push b
      @_dlen += b.length

  #----------------------

  _pop_block : (block_size) ->
    total = 0
    slices = []

    block_size or= @block_size

    getbuf = (buf, start, end) ->
      if not start and not end? then buf
      else if not end? then buf[start...]
      else buf[start...end]

    for b,i in @_buffers
      start = if i is 0 then @_p else 0
      stuff = b.length - start
      leftover = total + stuff - block_size
      if leftover < 0
        slices.push getbuf b, start
        total += stuff
      else if leftover is 0
        slices.push getbuf b, start
        total += stuff
        @_buffers = @_buffers[(i+1)...]
        @_p = 0
        break
      else
        end = b.length - leftover
        slices.push getbuf b, start, end
        @_buffers = @_buffers[i...]
        @_p = end
        break

    out = Buffer.concat slices
    assert (out.length is block_size)
    return out

  #----------------------
  
  _v_chunk : ({data, eof}, cb) ->
    @_input_len += data.length if data?
    @_push_data data
    err = out = null
    if eof
      await @_handle_eof defer err, out
    else if @_dlen >= @block_size
      await @_handle_block defer err, out
    cb err, out

  #----------------------
  
  _handle_eof : (cb) -> 
    esc = make_esc cb, "InBlocker::_v_chunk"
    i = 0
    outbufs = []

    bufs = []

    # First pop of the first partial buffer (if it's partial)
    bufs.push(@_buffers.shift()[@_p...]) if @_buffers.length and @_p > 0

    # Now consider all of the full buffers, and concat them
    # together into one.
    bufs = bufs.concat @_buffers
    buf = Buffer.concat bufs

    # Reset the internal state
    @_buffers = []
    @_dlen = 0
    @_p = 0

    eof = false
    until eof
      end = i + @block_size
      eof = end >= buf.length
      data = buf[i...end]
      await @_v_inblock_chunk { data, eof }, esc defer out
      outbufs.push out
      i = end
      
    out = Buffer.concat outbufs
    cb null, out

  #----------------------

  _handle_block : (cb) ->
    data = @_pop_block()
    await @_v_inblock_chunk { data, eof : false }, defer err, out
    cb err, out

#=========================================================

class Demux extends Base

  #----------------

  constructor : () ->
    @_buffers = []
    @_dlen = 0
    @_sink = null

  #----------------

  chunk : ({data,eof}, cb) ->
    err = out = null

    # IF we don't yet have a sink, we keep slurping in bytes until
    # we can demux
    if not @_sink?
      if data?
        @_buffers.push data
        @_dlen += data.length
      if @_dlen >= (pb = @peek_bytes())
        data = Buffer.concat @_buffers
        await @_demux { data, eof }, defer err, @_sink, data
        @_flowing = true
      else if eof
        err = new Error "EOF before #{pb} bytes"
        data = null

    # Once we have a sink, we shunt the data down into the sink.
    if @_sink?
      await @_sink.chunk { data, eof }, defer err, out

    cb err, out

#=========================================================

class Gets extends Base

  #-----------------------

  constructor : ({maxline,mod}) ->
    @_maxline = maxline
    @_mod = mod or 4
    @_buffers = []
    @_dlen = 0
    @_dummy_mode = false
    @_lineno = 0
    super()

  #-----------------------

  chunk : ({data, eof}, cb) ->
    err = null
    outbufs = []
    esc = make_esc cb, "Gets::chunk"

    if data? and (v = buf_indices_of(data, "\n".charCodeAt(0))).length
      prev = Buffer.concat @_buffers
      @_buffers = []
      @_dlen = 0
      start = 0
      for index in v
        line = bufcat [ prev, data[start...index] ]
        @_lineno++
        await @_v_line_chunk { data : line, newline : true, eof : false }, esc defer tmp
        outbufs.push tmp
        start = index + 1
        prev = null
      rest = data[start...]
      @_buffers = [ rest ]
      @_dlen = rest.length

    else if data? or eof 
      @_buffers.push data
      @_dlen += data.length
      chunk = null
      if @_maxline and (@_dlen > @_maxline)
        buf = Buffer.concat @_buffers
        retlen = Math.floor(@_dlen / @_mod)*@_mod
        chunk = buf[0...retlen]
        rest = buf[retlen...]
        @_buffers = [ rest ]
        @_dlen = rest.length
      if chunk? or eof
        await @_v_line_chunk { data : chunk, newline : false, eof }, esc defer tmp
        outbufs.push tmp

    cb err, bufcat(outbufs)

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

# Given a node.js-style Stream, make an XBT out of it
class ReverseAdapter extends Base

  constructor : ({@stream, hiwat}) ->
    super()
    @_buffers = []
    @_dlen = 0
    @_hiwat = hiwat or 0x10000

  _push_data : (data) -> 
    if data? and data.length
      @_buffers.push data
      @_dlen += data.length
      true
    else
      false

  _transform : (data, cb) ->
    await @stream.write data, defer()
    while (diff = @_hiwat - @_dlen) > 0 
      break unless @_push_data @stream.read diff
    cb()

  _flush : (cb) ->
    @stream.end()
    @stream.on 'data'    , (data) => @_push_data data
    @stream.once 'error' , (err ) -> cb err
    @stream.once 'end', (data) -> cb null

  _consume_bufs : () ->
    out = Buffer.concat @_buffers
    @_buffers = []
    @_dlen = 0
    out

  chunk : ({data, eof}, cb) ->
    esc = make_esc cb, "ReverseAdapter::chunk"
    await @_transform data, esc defer() if data?
    await @_flush esc defer() if eof
    cb null, @_consume_bufs()

#=========================================================

exports.Base = Base
exports.Chain = Chain
exports.SimpleInit = SimpleInit
exports.StreamAdapter = StreamAdapter
exports.ReverseAdapter = ReverseAdapter
exports.InBlocker = InBlocker
exports.Demux = Demux
exports.Passthrough = Passthrough
exports.Gets = Gets

#=========================================================
