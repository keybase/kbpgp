
xbt = require '../../xbt'
{bufcat} = require '../../util'
C = require('../../const').openpgp
{make_esc} = require 'iced-error'

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

exports.Depacketizer = class Depacketizer extends PgpReadBufferer

  constructor : ( { @packet_version, @packet_xbt } ) ->
    super {}
    @_total = 0
    @_flow_rem = 0
    @packet_xbt.set_parent(@)

  #-------------------------------------

  _depacketize_1 : (cb) ->
    esc = make_esc cb, "_depacketize_1"
    await @_find_length esc defer final, len
    await @_stream_packet final, len, esc defer()
    @_total += len
    cb null, final

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

  #-------------------------------------

  _depacketize_all : (cb) ->
    esc = make_esc cb, "_depacketize_all"
    final = false
    until final
      await @_depacketize_1 esc defer final
    cb null

  #-------------------------------------

  _stream_packet : (final, len, cb) ->
    rem = len
    esc = make_esc cb, "_stream_packet"
    while rem > 0
      await @_read { max : rem, min : 1}, esc defer data
      rem -= data.length
      eof = final and (rem is 0)
      await @packet_xbt.chunk { data, eof }, esc defer out
      @_buffer_out_data out
    cb null

  #-------------------------------------

  _parse_loop : (cb) ->
    await @_depacketize_all defer err
    cb err
    if not(@_err?) and not(@_eof)
      # At the end of a packet, we probably need to find the next packet, so we
      # call back to our parent (which has to be a Demux!) to do its next demux.
      @get_parent()._remux { indata : @_flush_in(), outdata : @_flush_out() }

#=================================================================================

exports.PacketParser = class PacketParser extends PgpReadBufferer

  constructor : ({@demux_klass}) ->
    super {}

  _get_next_demux : () ->
    unless (@_next_xbt)?
      @_next_xbt = new @demux_klass {}
      @_next_xbt.set_parent(@)
    @_next_xbt

  _parse_loop : (cb) ->
    await @_parse_header defer err
    @_switch_to_flow_mode()
    cb err

  _flow_demux : ({data, eof}, cb) ->
    console.log "flow demux"
    console.log eof
    console.log data
    console.log data.length
    await @_get_next_demux().chunk {data, eof}, defer err, data
    cb err, data

#=================================================================================

