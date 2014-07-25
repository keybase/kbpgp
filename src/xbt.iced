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
{Lock} = require './lock'

DEBUG = 1

#=========================================================

class Base

  @OBJ_ID : 0

  constructor : () ->
    @_parent = null
    @_metadata = {}
    @_hashers = []
    @_obj_id = Base.OBJ_ID++
    @_debug = 0

  chunk : ({data, eof}, cb) -> cb new Error "unimplemented!"

  #----------

  set_parent : (p) -> @_parent = p
  get_parent : () -> @_parent
  get_metadata : () -> @_metadata
  get_root_metadata : (slice, def) ->
    def or= {}
    md = @get_root()?.get_metadata() or {}
    if slice? then (md[slice] or= def)
    else md

  #----------

  set_root_metadata : ({slice, value}, cb) ->
    rmd = @get_root_metadata()
    err = null
    if (rmd[slice])? then err = new Error "Cannot have >1 '#{slice}' packets"
    else rmd[slice] = value
    cb err

  #----------

  # Work up the root of the XBT tree.
  get_root : () ->
    p = @get_parent()
    if not p? then @ else p.get_root()

  #----------

  push_hasher : (h) -> @_hashers.push(h)
  pop_hasher : (h) -> @_hashers.pop()
  hashers : () -> @_hashers

  #----------

  _get_debug_info : () ->
    unless @_debug_info?
      @_debug_info = if not DEBUG then {}
      else if not (p = @get_parent())?
        if @_debug then { level : 0, debug : @_debug }
        else {}
      else if (di = p._get_debug_info())? and di.debug
        { level : di.level + 1, debug : di.debug }
      else {}
    return @_debug_info

  #----------

  set_debug : (d) -> @get_root()._debug = d

  #----------

  _debug_prefix : (c) ->
    (c for [0..@_get_debug_info().level]).join('')

  #----------

  _debug_buffer : (b) ->
    if not (di = @_get_debug_info()).debug then null
    else if b?
      hex = b.toString 'hex'
      col = 80
      dat = if di.debug is 1 then (hex[0...col] + (if hex.length > col then "..." else '')) else hex
      "[#{b.length}]{#{dat}}"
    else "[]"

  #----------

  _chunk_debug_pre : ({data, eof}) ->
    if (di = @_get_debug_info()).debug
      prfx = @_debug_prefix("+")
      @_chunk_debug_msg prfx, "eof=#{eof}: #{@_debug_buffer(data)}"

  #----------

  _chunk_debug_post : ({err, data}) ->
    if (di = @_get_debug_info()).debug
      prfx = @_debug_prefix("-")
      msg_parts = []
      if err? then msg_parts.push "ERR=(#{err?.message})"
      msg_parts.push @_debug_buffer(data)
      @_chunk_debug_msg prfx, msg_parts.join(": ")

  #----------

  _chunk_debug_msg : (pre,post) ->
    console.log [ pre, "#{@xbt_type()}##{@_obj_id}", post ].join ' '

  #----------

  _debug_msg : (c, msg) ->
    if (di = @_get_debug_info()).debug
      prfx = @_debug_prefix(c)
      console.log [prfx, msg].join(" ")

#=========================================================

class Passthrough extends Base
  constructor : (args) ->
    super args

  xbt_type : () -> "Passthrough"

  chunk : ({data, eof}, cb) ->
    @_chunk_debug_pre { data, eof }
    cb null, data



#=========================================================

class Chain extends Base

  constructor : (links = []) ->
    @links = links
    for l in links
      l.set_parent(@)
    super()
    @_iters = 0

  xbt_type : () -> "Chain"

  push_xbt : (link) ->
    @links.push link
    link.set_parent @
    @

  chunk : ({data,eof}, cb) ->
    esc = make_esc cb, "Chain::chunk"
    out = null
    @_chunk_debug_pre { data, eof }
    for l,i in @links
      await l.chunk {data,eof}, esc defer data
      out = data
    @_chunk_debug_post { err : null, data : out }
    cb null, out

#=========================================================

class SimpleInit extends Base

  constructor : () ->
    @_did_init = false
    super()

  xbt_type : () -> "SimpleInit"

  init : (cb) ->
    err = data = null
    unless @_did_init
      @_did_init = true
      await @_v_init defer err, data
    cb err, data

  chunk : ({data,eof}, cb) ->
    @_chunk_debug_pre { data, eof }
    esc = make_esc cb, "SimpleInit::chunk"
    await @init esc defer init_data
    await @_v_chunk { data, eof }, esc defer out
    out = bufcat [ init_data, out ]
    @_chunk_debug_post { err : null , data : out }
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
    @_inq = new Queue()
    @_input_len = 0

  xbt_type : () -> "InBlocker"

  #----------------------

  _push_data : (b) -> @_inq.push(b)
  _pop_block : () -> @_inq.pull(@block_size)

  #----------------------

  _v_chunk : ({data, eof}, cb) ->
    @_chunk_debug_pre { data, eof }
    @_input_len += data.length if data?
    @_push_data data
    err = out = null
    if eof
      await @_handle_eof defer err, out
    else
      outbufs = []
      err = null
      while @_inq.n_bytes() >= @block_size and not err?
        await @_handle_block defer err, buf
        outbufs.push buf
      out = Buffer.concat outbufs
    @_chunk_debug_post { err, data : out }
    cb err, out

  #----------------------

  _handle_eof : (cb) ->
    esc = make_esc cb, "InBlocker::_v_chunk"
    i = 0
    outbufs = []
    buf = @_inq.flush()

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
    @_outbufs = []
    super()

  #----------------

  xbt_type : () -> "xbt.Demux"

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
    @_chunk_debug_pre { data, eof }

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

    @_chunk_debug_post { err, data : out }
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

  xbt_type : () -> "Gets"

  #-----------------------

  chunk : ({data, eof}, cb) ->
    err = null
    outbufs = []
    @_chunk_debug_pre { eof, data }
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

    data = bufcat(outbufs)
    @_chunk_debug_post { err, data }
    cb err, data

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
    @_hiwat = hiwat or 0x1000

  xbt_type : () -> "ReverseAdapter"

  _push_data : (data) ->
    if data? and data.length
      @_buffers.push data
      @_dlen += data.length
      true
    else
      false

  _transform : (data, cb) ->
    await @stream.write data, defer err
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
    @_chunk_debug_pre { data, eof}
    await @_transform data, esc defer() if data?
    await @_flush esc defer() if eof
    err = null
    data = @_consume_bufs()
    @_chunk_debug_post { err, data }
    cb err, data


#==============================================================

class Queue

  #---------

  constructor : (@_capacity) ->
    @_capacity or= 0x10000
    @_buffers = []
    @_dlen = 0
    @_i = 0
    @_wcb = null
    @_rcb = null
    @_wlock = new Lock
    @_rlock = new Lock

  #---------

  elongate : (n) ->
    @_capacity = Math.max n, @_capacity

  #---------

  push : (d) ->
    if d?.length
      @_buffers.push d
      @_dlen += d.length
    if (tmp = @_rcb)
      @_rcb = null
      tmp()

  #---------

  n_bytes : () -> @_dlen

  #---------

  pull : (n,peek) ->
    throw new Error "Bad argument to pull: #{n}" unless n?
    ret = if n >= @n_bytes() then @flush(peek)
    else @_pull(n,peek)
    if n > 0 and not peek then @_made_room()
    return ret

  #---------

  flush : (peek) ->
    list = if @_buffers.length and @_i then [ @_buffers[0][@_i...] ].concat(@_buffers[1...])
    else @_buffers
    out = Buffer.concat list
    @_i = 0
    if peek?
      @_buffers = [ out ]
    else
      @_dlen = 0
      @_buffers = []
    out

  #---------

  _made_room : () ->
    if @n_bytes() < @_capacity and (tmp = @_wcb)?
      @_wcb = null
      tmp()

  #---------

  wait_then_push : (data, cb) ->
    await @_wlock.acquire defer()
    await @wait_for_room defer()
    @push data
    @_wlock.release()
    cb()

  #---------

  wait_then_read : ({min,max,peek, is_eof}, cb) ->
    await @_rlock.acquire defer()
    @elongate min
    await @wait_for_data {n : min, is_eof, peek}, defer err
    data = if err? then null else @pull(max, peek)
    @_rlock.release()
    cb err, data

  #---------

  wait_for_room : (cb) ->
    if @n_bytes() < @_capacity
      cb()
    else
      throw new Error "Can't ovewrite @_wcb in buffer" if @_wcb
      @_wcb = cb

  #---------

  wait_for_data : ({n, is_eof, peek}, cb) ->
    while @n_bytes() < n and (not(is_eof) or not(is_eof()))
      throw new Error "refusing to overwrite @_rcb" if @_rcb?
      await @_rcb = defer()
    err = if (@n_bytes() >= n) or peek then null else new Error "EOF before #{n} bytes"
    cb err

  #---------

  _pull : (n, peek) ->
    slices = []
    total = 0

    getbuf = (buf, start, end) ->
      if not start and not end? then buf
      else if not end? then buf[start...]
      else buf[start...end]

    for b,i in @_buffers
      start = if i is 0 then @_i else 0
      stuff = b.length - start
      leftover = total + stuff - n
      if leftover < 0
        total += stuff
        slices.push getbuf b, start
      else if leftover is 0
        slices.push getbuf b, start
        unless peek
          @_buffers = @_buffers[(i+1)...]
          @_i = 0
        break
      else
        end = b.length - leftover
        slices.push getbuf b, start, end
        unless peek
          @_buffers = @_buffers[i...]
          @_i = end
        break

    out = Buffer.concat slices
    assert (out.length is n)
    unless peek
      @_dlen -= n

    return out

#==============================================================

class Waitpoint

  constructor : () ->
    @_hit = false
    @_cb = null

  trigger : () ->
    @_hit = true
    if (tmp = @_cb)
      @_cb = null
      tmp()

  wait : (cb) ->
    if @_hit then cb()
    else
      throw err "Can't wait, someone is already waiting!" if @_cb?
      @_cb = cb

#==============================================================

class ReadBufferer extends Base

  constructor : ({bufsz}) ->
    @_inq = new Queue bufsz
    @_outq = new Queue
    @_source_eof = false
    @_internal_eof = false
    @_err = null
    @_main_done = false
    @_done_main_waitpoint = new Waitpoint
    @_source_eof_waitpoint = new Waitpoint
    super()

  #---------------------------

  xbt_type : () -> "ReadBufferrer"

  #---------------------------

  _emit : ({data, eof}, cb) ->
    @_internal_eof = eof
    await @_outq.wait_then_push data, defer()
    cb null

  #---------------------------

  _push_data : ({data, eof}, cb) ->
    await @_inq.wait_then_push data, defer()
    cb null

  #---------------------------

  _is_eof : () -> @_source_eof

  #---------------------------

  _pass_through : (cb) ->
    next = new Passthrough()
    await @_stream_to next, defer()
    cb()

  #---------------------------

  _stream_to : (next, cb) ->
    @_sink = next
    data = @_inq.flush()
    await @_sink.chunk { data, eof : @_source_eof }, defer err, out
    unless err?
      await @_emit { data : out, eof : false }, defer()
    await @_source_eof_waitpoint.wait defer()
    cb err

  #---------------------------

  run : (cb) -> throw new Error "unimplemented!"

  #---------------------------

  _run_main_loop : () ->
    unless @_running
      @_running = true
      await @run defer @_err
      @_done_main_waitpoint.trigger()

  #---------------------------

  chunk : ({data, eof}, cb) ->
    @_chunk_debug_pre { data, eof}
    @_run_main_loop()
    @_source_eof = true if eof
    outdata = null

    if @_sink?
      await @_sink.chunk { data, eof }, defer err, outdata
    else
      await @_push_data { data, eof  }, defer err

    if eof
      @_source_eof_waitpoint.trigger()
      await @_done_main_waitpoint.wait defer()

    err = @_err if not err?
    data = bufcat [ @_outq.flush(), outdata ]
    @_chunk_debug_post { err, data }
    cb err, data

  #---------------------------

  _peek : (i, cb) -> @_read { exactly : i, peek : true }, cb

  #---------------------------

  _read : ({min,max,exactly,peek},cb) ->
    throw new Error "Bad arguments to _read" unless exactly? or (min? and max?)
    if exactly? then min = max = exactly
    is_eof = () => @_source_eof
    await @_inq.wait_then_read { min, max, peek, is_eof }, defer err, data
    cb err, data

#==============================================================

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

#===============================================================
