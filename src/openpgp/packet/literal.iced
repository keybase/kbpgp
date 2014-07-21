
{OutStream,Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
{uint_to_buffer} = require '../../util'
{Packetizer} = require './xbt_packetizer'
{PacketParser} = require './xbt_depacketizer'
{make_esc} = require 'iced-error'

#=================================================================================

# 5.9.  Literal Data Packet (Tag 11)
class Literal extends Packet

  @TAG : C.packet_tags.literal
  TAG : Literal.TAG

  #--------

  constructor : ( { @format, @filename, @date, @data} ) ->
    super()

  #--------

  @parse : (slice) -> (new LiteralParser slice).parse()

  #--------

  toString : () -> @data.toString @buffer_format()

  #--------

  buffer_format : () ->
    switch @format 
      when C.literal_formats.text then 'ascii' 
      when C.literal_formats.utf8 then 'utf8'
      else 'binary'

  #--------

  to_signature_payload : () -> Buffer.concat [ @data ]

  #--------

  write_unframed : (cb) ->
    @filename or= new Buffer []
    bufs = [
      new Buffer([@format]),
      uint_to_buffer(8,@filename.length)
      @filename,
      uint_to_buffer(32, @date),
    ]

    # For streaming cases, there won't be any data!
    bufs.push(@data) if @data?

    ret = Buffer.concat bufs
    cb null, ret

  #--------

  to_literal : () -> @

  #--------

  new_xbt : () -> new XbtOut { packet : @ }
  @new_xbt_parser : (arg) -> new XbtIn arg

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
    throw new Error "unknown format: #{format}" unless format in known_formats
    filename = @slice.read_string()
    date = @slice.read_uint32()
    data = @slice.consume_rest_to_buffer()

    new Literal { format , filename, date, data }

#=================================================================================

exports.XbtOut = XbtOut = Packetizer

#=================================================================================

class XbtIn extends PacketParser

  constructor : () ->
    super {}

  _parse_header : (cb) ->
    esc = make_esc cb, "XbtIn::Depacketizer"
    err = null
    await @_read_uint8  esc defer format
    await @_read_string esc defer filename
    await @_read_uint32 esc defer date
    if (rmd = @get_root_metadata())?
      err = new Error "Cannot have >1 literal in a stream"
    else 
      rmd.literal = { format, filename, date }
    cb err

  _flow : ({data, eof}, cb) -> 
    cb null, data

#=================================================================================

exports.Literal = Literal

#=================================================================================

