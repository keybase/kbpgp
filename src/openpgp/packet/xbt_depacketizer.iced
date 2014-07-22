
xbt = require '../../xbt'
{bufcat} = require '../../util'
C = require('../../const').openpgp
{make_esc} = require 'iced-error'

#=================================================================================

class PgpReadBufferer extends xbt.PullBase

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

  constructor : ( { @packet_version } ) ->
    super {}
    @_total = 0

  #-------------------------------------

  run : (cb) ->
    final = false
    esc = make_esc cb, "_depacketize_1"
    until final
      await @_find_length esc defer final, len
      await @_read len, esc defer data
      @_total += len
      await @_emit { data, eof : final }, esc defer()
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

exports.PacketParser = class PacketParser extends PgpReadBufferer

  constructor : () ->
    super {}

  run : (cb) ->
    esc = make_esc cb, "PacketParser::_process"
    await @_process_header esc defer()
    await @_pass_through esc defer()
    cb null
    
#=================================================================================

