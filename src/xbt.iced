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
    @_parent = null
    @_metadata = {}

  chunk : ({data, eof}, cb) -> cb new Error "unimplemented!"

  set_parent : (p) -> @_parent = p
  get_parent : () -> @_parent
  get_metadata : () -> @_metadata
  get_root_metadata : (slice, def) -> 
    def or= {}
    md = @root()?.get_metadata() or {}
    if slice? then (md[slice] or= def)
    else md

  # Work up the root of the XBT tree. 
  root : () ->
    p = @get_parent()
    if not p? then @ else p.root()

#=========================================================

class Passthrough extends Base
  chunk : ({data, eof}, cb) -> cb null, data

#=========================================================

class Chain extends Base

  constructor : () ->
    @links = []

  push_xbt : (link) ->
    @links.push link
    link.set_parent @
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

#
# An XBT that splits a stream into fixed-sized blocks, and
# returns only blocks of that size.  With every block to be
# emitted, it calls _v_inblock_chunk.  This is mainly used
# with outputting to Base64-armoring, since we want to encode
# blocks of 48-bytes into lines of 64-byte output.
#
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

# A class that allows a subclass to pull at will, and not to have
# data constantly pushed at it.  To change from a pushee to a puller,
# we need a buffer in between.
#
# Note this XBT can be in one of two states: pull mode, which is the default,
# and flow mode, which can be turned on, and just causes data to flow as 
# in a normal XBT. Parsers that parse headers and then flow data will want to 
# start in the first mode, and switch to flow.
class ReadBufferer extends Base

  constructor : ({capacity}) ->
    @_capacity = capacity or 0x10000
    @_flow_mode = false
    @_buffers = []
    @_dlen = 0
    @_eof = false
    @_err = null
    @_pusher_cb = @_puller_cb = null
    @_flow_data_prepend = null
    @_first = true
    @_outbufs = []
    @_last_cb = null
    super()

  #-------------------------------

  _fire : (which, args = []) ->
    if (cb = @[which])?
      @[which] = null
      cb args...

  #-------------------------------

  _read : ({min,max,exactly}, cb) ->
    if exactly? then min = max = exactly
    @_capacity = Math.max @_capacity, min

    while min > @_dlen and not(@_eof) and not(@_err?)
      await @_puller_cb = defer()

    out = null

    if @_err then # noop
    else if @_eof and min > @_dlen 
      @_err = new Error "EOF before read satisfied"
    else
      buf = @_flush_in()
      out = buf[0...max]
      rest = buf[max...]
      @_buffers = if rest.length then [ rest ] else []
      @_dlen = rest.length

    @_fire '_pusher_cb'
    cb @_err, out

  #-------------------------------

  _flush_out : () ->
    out = Buffer.concat @_outbufs
    @_outbufs = []
    out

  #-------------------------------

  _flush_in : () ->
    @_dlen = 0
    @_fire '_pusher_cb'
    out = Buffer.concat @_buffers
    @_dlen = 0
    @_buffers = []
    out

  #-------------------------------

  _switch_to_flow_mode : () ->
    @_flow_mode = true

  #-------------------------------

  _chunk_parse_mode : ({data, eof}, cb) ->
    if data?.length
      while (@_dlen > @_capacity) and not(@_err?) and not(@_flow_mode)
        await @_pusher_cb = defer()
      @_buffer_in_data(data)
    @_eof = true if eof
    # Tricky; we need to set this before we poke the puller back into action,
    # in case the puller uses up the rest of the parsed data and then moves
    # into flow mode.
    if eof
      @_last_cb = cb
    @_fire '_puller_cb'
    if not eof
      cb null, @_flush_out()

  #-------------------------------

  _buffer_out_data : (buf) ->
    if buf?.length
      @_outbufs.push buf

  #-------------------------------

  _buffer_in_data : (buf) ->
    if buf?.length
      @_buffers.push buf
      @_dlen += buf.length

  #-------------------------------

  _run_parse_loop : () ->
    if @_first
      @_first = false
      await @_parse_loop defer @_err
      if (tmp = @_last_cb)
        @_last_cb = null
        if @_flow_mode
          @_chunk_flow_mode { eof : true }, tmp
        else
          tmp @_err, @_flush_out()

  #-------------------------------

  chunk : ( {data, eof}, cb) ->
    @_run_parse_loop()

    # Once we're stuck in an error situation, we can't proceed.
    if @_err then            cb @_err, null
    else if @_flow_mode then @_chunk_flow_mode { data, eof}, cb
    else                     @_chunk_parse_mode { data, eof}, cb

  #-------------------------------

  _chunk_flow_mode : ({data, eof}, cb) ->
    data = bufcat [ @_flush_in(), data ]
    @_flow_data_prepend = null
    await @_flow { data, eof }, defer err, out
    out = bufcat [ @_flush_out(), out ]
    cb err, out

#=========================================================

class Demux extends Base

  #----------------

  constructor : () ->
    @_buffers = []
    @_dlen = 0
    @_sink = null
    @_outbufs = []
    super()

  #----------------

  _remux : ({data, outdata}) ->
    if indata?.length
      @_buffers.push indata
      @_dlen += indata.length
    if outdata.length?
      @_outbufs.push outdata
    @_sink = null

  #----------------

  _flush_out : () ->
    out = Buffer.concat @_outbufs
    @_outbufs = []
    out

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
        @_buffers = []
        @_dlen = 0
        await @_demux { data, eof }, defer err, @_sink, data
        @_sink?.set_parent(@)
      else if eof and @_dlen
        err = new Error "EOF before #{pb} bytes (had #{@_dlen} ready)"
        data = null

    # Once we have a sink, we shunt the data down into the sink.
    if @_sink?
      await @_sink.chunk { data, eof }, defer err, out
      out = bufcat [ @_flush_out(), out ]

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
      if data?
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
exports.ReadBufferer = ReadBufferer

#=========================================================
