
{Base} = require './xbt'

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
    if n >= @n_bytes() then @flush(peek)
    else @_pull(n,peel)
    if n > 0 and not peek then @_made_room()

  #---------

  flush : (peek) ->
    list = if @_buffers.length and @_i then [ @_buffers[0][@_i...], @_buffers[1...] ]
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

  wait_for_room : (cb) ->
    if @n_bytes() < @_capacity then cb()
    else @_wcb = cb

  #---------

  wait_for_data : (n, is_eof, cb) ->
    while @n_bytes() < n and (not(is_eof) or not(is_eof()))
      await @_rcb = defer()
    err = if @n_bytes() < n then new Error "EOF before #{n} bytes" else null
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
      leftover = total + stuff - block_size
      if leftover < 0
        slices.push getbuf b, start
        total += stuff
      else if leftover is 0
        slices.push getbuf b, start
        total += stuff
        @_buffers = @_buffers[(i+1)...]
        @_i = 0
        break
      else
        end = b.length - leftover
        slices.push getbuf b, start, end
        @_buffers = @_buffers[i...]
        @_i = end
        break

    out = Buffer.concat slices
    assert (out.length is n)
    if peek
      @_buffers.unshift out
    else
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
    else @_cb = cb

#==============================================================

class PullBase extends Base

  constructor : ({sink, bufsz}) ->
    @_sink = sink
    @_inq = new Queue bufsz
    @_outq = new Queue 
    @_source_eof = false
    @_internal_eof = false
    @_err = null
    @_main_done = false
    @_pass_through = false
    @_done_main_waitpoint = new Waitpoint
    @_source_eof_waitpoint = new Waitpoint

  #---------------------------

  _emit : ({data, eof}, cb) ->
    @_internal_eof = eof
    await @_outq.wait_for_room defer()
    @_outq.push(data)
    cb null

  #---------------------------

  _push_data : ({data, eof}, cb) ->
    await @_inq.wait_for_room defer()
    @_inq.push data 
    cb null

  #---------------------------

  set : ({source, inq, sink}) ->
    @_source = source if source?
    @_inq = inq if inq?
    @_sink = sink if sink?

  #---------------------------

  _pass_through : (cb) ->
    await @_stream_to null, defer()
    cb()

  #---------------------------

  _stream_to : (next, cb) ->
    @_do_pass_through = true
    if next?
      next._inq = @_inq
      @_sink = next
    await @_source_eof_waitpoint.wait defer()
    cb null

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
    @_run_main_loop()
    @_source_eof = true if eof
    outdata = null

    if not @_do_pass_through
      await @_push_data { data, eof }, defer err
    else if @_sink?
      await @_sink.chunk { data, eof}, defer err, outdata
    else
      outdata = bufcat [ @_inq.flush(), data ]

    if eof
      @_source_eof_waitpoint.trigger()
      await @_done_main_waitpoint.wait defer()

    cb @_err, bufcat [ @_outq.flush(), outdata ]

  #---------------------------

  _peek : (i, cb) -> @_read { exactly : i, peek : true }, cb

  #---------------------------

  _read : ({min,max,exactly,peek},cb) ->
    if exactly? then min = max = exactly
    @_inq.elongate min
    await @_inq.wait_for_data min, ( () => @_source_eof ), defer err
    data = if err? then null else @_inq.pull(max, peek)
    cb err, data

#==============================================================
