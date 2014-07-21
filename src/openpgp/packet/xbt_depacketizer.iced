
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

  #-------------------------

  read_uint8 : (cb) ->
    await @read 1, defer err, buf
    out = if err? then null else buf.readUInt8(0)
    cb err, out

  #-------------------------

  read_uint16 : (cb) ->
    await @read 2, defer err, buf
    out = if err? then null else buf.readUInt16BE(0)
    cb err, out

  #-------------------------

  read_at_most : (n, cb) ->
    err = null
    if n > @_dlen
      out = @flush()
    else
      await @read n, defer err, out
    cb err, out

  #-------------------------

  read_uint32 : (cb) ->
    await @read 4, defer err, buf
    out = if err? then null else buf.readUInt32BE(0)
    cb err, out

  #-------------------------

  read_string : (cb) ->
    esc = make_esc cb, "_read_string"
    await @read_uint8 esc defer len
    await @read len, esc defer buf
    cb null, buf

  #-------------------------------

  flush : () ->
    @_dlen = 0
    @fire '_pusher_cb'
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
    @_eof = true if eof
    @fire '_puller_cb'
    cb null

#=================================================================================

exports.Depacketizer = class Depacketizer extends xbt.Base

  constructor : ( { @packet_version } ) ->
    super()
    @_read_buffer = new ReadBuffer()

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
    # XXX write me


#=================================================================================

exports.PacketParser = class PacketParser extends Depacketizer

  #-------------------------
  
  constructor : ({packet_version}) ->
    super { packet_version }
    @_read_buffer = new ReadBuffer()
    @_state = 0
    @_prebuf = null
    @_finish_header_cb = null

  #-------------------------
  
  _run : () ->
    @_state = 1
    await @_parse_header defer @_err
    @_prebuf = @_read_buffer.flush()
    @_state = 2 
    if (tmp = @_finish_header_cb)?
      @_finish_header_cb = null
      tmp()

  #-------------------------

  _pump_data : ({data, eof}, cb) ->
    err = out = null
    if @_err then err = @_err
    else if @_state is 1
      await 
        if eof
          @_finish_header_cb = defer()
        @_read_buffer.push { data, eof }, defer err
    if not(@_err?) and (@_state is 2)
      data = bufcat [ @_prebuf, data ] 
      await @_flow { data, eof }, defer err, out
    @_err = err if err?
    cb err, out

  #-------------------------
  
  _v_chunk : ({data, eof}, cb) ->
    @_run() unless @_state
    @_pump_data { data, eof }, cb

#=================================================================================

