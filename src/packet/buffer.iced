
#================================================================================================

class SlicerBuffer

  constructor : (@buf, @start = 0) ->
    @i = @start
    @end = null

  clamp : (pos) -> @end = pos

  len : () -> @buf.length - @start
  rem : () -> @buf.length - @i
  offset : () -> @i - @start
  check : () -> throw new Error "read off the end of the packet @#{@i}" if @end? and @i > @end
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
  read_buffer : (l) ->
    ret = @buf[@i...(@i+l)]
    @i += l
    @check()
    ret
  rest : () -> 
    @start = @i
  peek_rest_to_buffer : () ->
    @buf[@i...]
  advance : (i = 1) -> @i += i

  peek_uint8 : () -> @buf.readUInt8 @i

  read_v4_length : () ->
    p = @slice.peek_uint8()
    if p < 192       then @slice.advance(1); p
    else if p < 224  then @slice.read_uint16() - (192 << 8) + 192
    else if p < 0xff then @slice.advance(1); (1 << (p & 0x1f))
    else                  @slice.read_uint32()

#================================================================================================

exports.SlicerBuffer = SlicerBuffer

#================================================================================================

