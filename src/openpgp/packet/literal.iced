
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
{uint_to_buffer} = require '../../util'

#=================================================================================

# 5.9.  Literal Data Packet (Tag 11)
class Literal extends Packet

  constructor : ( { @format, @filename, @date, @data} ) ->
    super()

  @parse : (slice) -> (new LiteralParser slice).parse()

  toString : (encoding = null) -> @data.toString (encoding or @buffer_format())
  toBuffer : () -> @data

  buffer_format : () ->
    switch @format
      when C.literal_formats.text then 'ascii'
      when C.literal_formats.utf8 then 'utf8'
      else 'binary'

  to_signature_payload : () -> Buffer.concat [ @data ]

  write_unframed : (cb) ->
    @filename or= new Buffer []
    bufs = [
      new Buffer([@format]),
      uint_to_buffer(8,@filename.length)
      @filename,
      uint_to_buffer(32, @date),
      @data
    ]
    ret = Buffer.concat bufs
    cb null, ret

  write : (cb) ->
    err = ret = null
    await @write_unframed defer err, raw
    ret = @frame_packet C.packet_tags.literal, raw unless err?
    cb err, ret

  to_literal : () -> @

#=================================================================================

class LiteralParser

  constructor : (@slice) ->

  #  The body of this packet consists of:
  #
  #   - A one-octet version number.  The only currently defined value is 1.
  #   - Encrypted data, the output of the selected symmetric-key cipher
  #     operating in Cipher Feedback mode with shift amount equal to the
  #     block size of the cipher (CFB-n where n is the block size).
  parse : () ->
    known_formats = (v for k,v of C.literal_formats)
    format = @slice.read_uint8()
    throw new Error "unknwon format: #{format}" unless format in known_formats
    filename = @slice.read_string()
    date = @slice.read_uint32()
    data = @slice.consume_rest_to_buffer()

    new Literal { format , filename, date, data }

#=================================================================================

exports.Literal = Literal

#=================================================================================

