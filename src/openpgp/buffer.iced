
#================================================================================================

class SlicerBuffer

  constructor : (@buf, @start = 0) ->
    throw new Error 'need a Buffer!' unless Buffer.isBuffer @buf
    @i = @start
    @_end = null

  clamp : (len) -> 
    ret = @_end
    @_end = @i + len 
    ret
  unclamp : (e) -> 
    @start = @i
    @_end = e

  len : () -> @buf.length - @start
  rem : () -> @buf.length - @i
  offset : () -> @i - @start
  check : () -> 
    if (@_end and @i > @_end) or (@i > @buf.length)
      throw new Error "read off the end of the packet @#{@i}/#{@buf.length}/#{@_end}"
  read_uint8 : () -> 
    ret = @buf.readUInt8 @i++
    @check()
    ret
  read_uint16 : () -> 
    ret = @buf.readUInt16BE @i
    @i += 2
    @check()
    ret
  read_uint32 : () ->
    ret = @buf.readUInt32BE @i
    @i += 4
    @check()
    ret
  read_buffer_at_most : (l) ->
    @read_buffer (Math.min(l, @rem()))
  read_buffer : (l) ->
    ret = @buf[@i...(@i+l)]
    @i += l
    @check()
    ret
  end : () -> @_end or @buf.length
  peek_rest_to_buffer : () -> @buf[@i...@end()]
  consume_rest_to_buffer : () ->
    ret = @peek_rest_to_buffer()
    @i = @end()
    ret
  advance : (i = 1) -> @i += i
  peek_to_buffer : (len) -> @buf[@i...(@i + len)]

  peek_uint8 : () -> @buf.readUInt8 @i
  peek_uint16 : () -> @buf.readUInt16BE @i

  read_string : () -> @read_buffer @read_uint8()

  read_v4_length : () ->
    p = @peek_uint8()
    five_byte = false
    len = if p < 192  then @advance(1); p
    else  if p < 224  then @read_uint16() - (192 << 8) + 192
    else  if p < 0xff then @advance(1); (1 << (p & 0x1f))
    else                   @advance(1); five_byte = true; @read_uint32()
    [len, five_byte]

#================================================================================================

exports.SlicerBuffer = SlicerBuffer

#================================================================================================

