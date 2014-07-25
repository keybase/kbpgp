
xbt = require '../../xbt'
{akatch,bufcat} = require '../../util'
C = require('../../const').openpgp
{make_esc} = require 'iced-error'
{SlicerBuffer} = require '../buffer'

#=================================================================================

class PgpReadBufferer extends xbt.ReadBufferer

  #-------------------------

  _read_uint8 : (cb) ->
    await @_read { exactly : 1}, defer err, buf
    out = if err? then null else buf.readUInt8(0)
    cb err, out

  #-------------------------

  _read_uint16 : (cb) ->
    await @_read { exactly : 2}, defer err, buf
    out = if err? then null else buf.readUInt16BE(0)
    cb err, out

  #-------------------------

  _read_uint32 : (cb) ->
    await @_read { exactly : 4}, defer err, buf
    out = if err? then null else buf.readUInt32BE(0)
    cb err, out

  #-------------------------

  _read_string : (cb) ->
    esc = make_esc cb, "_read_string"
    await @_read_uint8 esc defer len
    await @_read { exactly : len}, esc defer buf
    cb null, buf

#=================================================================================

class BaseDepacketizer extends PgpReadBufferer

  constructor : ( { @packet_version, @demux_klass } ) ->
    super {}
    @_total = 0

  #-------------------------------------

  xbt_type  : () -> "BaseDepacketizer"

  #-------------------------------------

  _next : (cb) ->
    err = null
    if not @_is_eof() or @_inq.n_bytes()
      demux = new @demux_klass {}
      demux.set_parent(@)
      await @_stream_to demux, defer err
    cb err

  #-------------------------------------

  run : (cb) ->
    final = false
    esc = make_esc cb, "_depacketize_1"
    until final
      @_debug_msg "|", "Depacketizer.run --> find_length"
      await @_find_length esc defer final, len
      @_debug_msg "|", "Depacketizer.run <-- #{final} #{len}"
      await @_read { exactly : len}, esc defer data
      @_debug_msg "|", "Depacketizer.run <-- read #{@_debug_buffer(data)}"
      @_total += len
      await @_pkt_emit { data, eof : final }, esc defer()

    await @_pkt_eof esc defer()
    await @_next esc defer()

    cb null

  #-------------------------------------

  _find_length : (cb) ->
    esc = make_esc cb, "_find_length"
    await @_read_uint8 esc defer tag
    err = ret = null
    final = true
    if @packet_version is C.packet_version.old
      nxt = switch (tag & 0x03)
        when 0 then @_read_uint8.bind(@)
        when 1 then @_read_uint16.bind(@)
        when 2 then @_read_uint32.bind(@)
        else
          err = new Error "Cannot handle old-style wildcard lengths"
          null
      if nxt?
        await nxt esc defer ret
    else
      # discard 'tag', it's not needed in this case
      await @_read_uint8 esc defer first
      if first < 192 then ret = first
      else if first is 255
        await @_read_uint32 esc defer ret
      else if first < 224
        await @_read_uint8 esc defer second
        ret = ((first - 192) << 8) + (second + 192)
      else
        ret = 1 << (first & 0x1f)
        final = false
    cb err, final, ret

#=================================================================================

exports.StreamingDepacketizer = class StreamingDepacketizer extends BaseDepacketizer

  constructor : ( { packet_version, demux_klass, @packet_xbt } ) ->
    super { packet_version, demux_klass }
    @packet_xbt.set_parent(@)
    @_total = 0

  #-------------------------------------

  xbt_type  : () -> "StreamingDepacketizer"

  #-------------------------------------

  _pkt_emit : ( { data, eof}, cb) ->
    await @packet_xbt.chunk { data, eof }, defer err, data
    await @_emit { data, eof}, defer()
    cb err

  #-------------------------------------

  _pkt_eof : (cb) -> cb null

#=================================================================================

exports.SmallDepacketizer = class SmallDepacketizer extends BaseDepacketizer

  constructor : ( { packet_version, demux_klass, @packet_klass } ) ->
    super { packet_version, demux_klass }
    @_total = 0
    @_bufs = []

  #-------------------------------------

  xbt_type  : () -> "SmallDepacketizer"

  #-------------------------------------

  _pkt_emit : ( { data, eof}, cb) ->
    @_bufs.push data
    cb null

  #-------------------------------------

  _pkt_eof : (cb) ->
    esc = make_esc cb, "SmallDepacketizer::_pkt_eof"
    buf = Buffer.concat @_bufs
    @_bufs = []
    sb = new SlicerBuffer buf
    await akatch ( () => @packet_klass.parse sb, {streaming : true }), esc defer packet
    await packet.finish_xbt_packet { xbt : @ }, esc defer()
    cb null

#=================================================================================

exports.PacketParser = class PacketParser extends PgpReadBufferer

  constructor : ({@demux_klass}) ->
    super {}

  xbt_type  : () -> "PacketParser"

  _run_body : (cb) -> cb new Error "not implemented!"

  run : (cb) ->
    esc = make_esc cb, "PacketParser::_process"
    await @_parse_header esc defer()
    await @_run_body esc defer()
    cb null

#=================================================================================

