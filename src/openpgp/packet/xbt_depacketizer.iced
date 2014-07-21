
xbt = require '../../xbt'
{bufcat} = require '../../util'

#=================================================================================

class ReadBuffer

  constructor : (@_capacity = 0x1000) ->
    @_buffers = []
    @_dlen = 0
    @_eof = false
    @_err = null
    @_pusher_cb = @_puller_cb = null

  #-------------------------------

  fire : (which) ->
    if (cb = @[which])?
      @[which] = null
      cb()

  #-------------------------------

  read : (len, cb) ->
    @_capacity = Math.max @_capacity, len

    while len > @_dlen and not(@_eof) and not(@_err?)
      await @_puller_cb = defer()

    out = null

    if @_err then # noop
    else if eof and len > @_dlen then @_err = new Error "EOF before read satisfied"
    else
      buf = @flush()
      out = buf[0...len]
      rest = buf[len...]
      @_buffers = [ rest ]
      @_dlen = rest.length

    @fire '_pusher_cb'
    cb @_err, out

  #-------------------------------

  flush : () ->
    out = Buffer.concat @_buffers
    @_dlen = 0
    @_buffers = []
    out

  #-------------------------------

  push : ({data, eof}, cb) ->
    if data?.length
      while (@_dlen > @_capacity) and not(@_err?)
        await @_pusher_cb = defer()
      @_buffers.push data
      @_dlen += data.length
      @fire '_puller_cb'
    @_eof = true if eof
    cb null

#=================================================================================

exports.Depacketizer = class Depacketizer extends xbt.Base

  constructor : ( { @packet_version } ) ->
    super()
    @_total = 0

  _depacketize_1 : (cb) ->
    esc = make_esc cb, "_depacketize_1"
    await @_find_length esc defer final, len
    await @_stream_packet len, esc defer()
    @_total += len
    cb null, final

  _depacketize_all : (cb) ->
    esc = make_esc cb, "_depacketize_all"
    final = false
    until final
      await @_depacketize_1 esc defer final
    cb null


  chunk : ({data,eof}, cb) ->


#=================================================================================

exports.PacketParser = class PacketParser extends Depacketizer

  #-------------------------
  
  constructor : ({packet_version}) ->
    super { packet_version }
    @_read_buffer = new ReadBuffer @
    @_state = 0
    @_consumer_cb = @_producer_cb = null 
    @_buffers = []
    @_dlen = 0

  #-------------------------
  
  _run : () ->
    @_state = 1
    await @_parse_header defer @_err
    if (tmp = @_producer_cb)
      @_producer_cb = null
      tmp @_err, @_flush_buffers()
    @_state = 2 

  #-------------------------

  _flush_buffers : () ->
    out = Buffer.concat @_buffers
    @_dlen = 0
    @_buffers = []
    out

  #-------------------------

  _shift_data : (len) ->
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
      [err, out] = @_shift_data(len)
    cb err, out

  #-------------------------

  _read_uint8 : (cb) ->
    await @_read_data 1, defer err, buf
    out = if err? then null else buf.readUInt8(0)
    cb err, out

  #-------------------------

  _read_uint16 : (cb) ->
    await @_read_data 2, defer err, buf
    out = if err? then null else buf.readUInt16BE(0)
    cb err, out

  #-------------------------

  _read_uint32 : (cb) ->
    await @_read_data 4, defer err, buf
    out = if err? then null else buf.readUInt32BE(0)
    cb err, out

  #-------------------------

  _read_string : (cb) ->
    esc = make_esc cb, "_read_string"
    await @_read_uint8 esc defer len
    await @_read_data len, esc defer buf
    cb null, buf

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
      if @_dlen
        data = bufcat [ @_flush_buffers(), data ]
      @_flow { data, eof }, cb 

  #-------------------------
  
  _v_chunk : ({data, eof}, cb) ->
    @_run() unless @_state
    @_pump_data { data, eof }, cb

#=================================================================================

