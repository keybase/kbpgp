
xbt = require '../../xbt'

exports.Depacketizer = class Depacketizer extends xbt.Base

#=================================================================================

exports.PacketParser = class PacketParser extends Depacketizer

  #-------------------------
  
  constructor : ({packet_version}) ->
    super { packet_version }
    @_state = 0
    @_consumer_cb = @_producer_cb = null 
    @_buffers = []
    @_dlen = 0

  #-------------------------
  
  _run : () ->
    @_state = 1
    await @_parse_header defer @_err
    @_flush()
    @_state = 2 

  #-------------------------

  _pop_data : (len) ->
    err = out = null
    if @_buffers.length is 0
      err = new Error "No data, can't pop"
    else if @_dlen < len
      err = new Error "Buffer underrun; unexpected"
    else if @_buffers.length > 1
      buf = [ Buffer.concat(@_buffers) ]
    else
      buf = @_buffers[0]
    unless err?
      out = buf[0...len]
      @_buffers = [ buf[len...] ]
      @_dlen -= len
    cb err, out

  #-------------------------

  _read_data : (len, cb) ->
    err = null
    while @_dlen < len and not err?
      if @_eof
        err = new Error "EOF in read"
      else
        await 
          @_consumer_cb = defer()
          if (tmp = @_producer_cb)?
            @_producer_cb = null
            tmp()
    if not err?
      [err, out] = @_pop_data(len)
    cb err, out

  #-------------------------

  _pump_data : ({data, eof}, cb) ->
    if @_err then cb @_err
    else if @_state is 1
      @_buffers.push data
      @_dlen += data.length
      @_eof = eof
      @_producer_cb = cb
      if (tmp = @_consumer_cb)?
        @_consumer_cb = null
        tmp()
    else
      @_flow { data, eof }, cb 

  #-------------------------
  
  _v_chunk : ({data, eof}, cb) ->
    @_run() unless @_state
    @_pump_data { data, eof }, cb

#=================================================================================

