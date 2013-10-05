
util = require '../util'
{SlicerBuffer} = require './buffer'
C = require('../const').openpgp

#==================================================================================================

class Packet

  #----------------------

  constructor : () ->

  #----------------------
   
  frame_packet : (tag, body) ->
    bufs = [
      new Buffer([ (0xc0 | tag) ]),
      util.encode_length(body.length),
      body
    ]
    Buffer.concat bufs

  #----------------------

  set_lengths : (real_packet_len, header_len) ->
    @real_packet_len = real_packet_len
    @header_len = header_len

  #----------------------

  set_tag : (t) -> @tag = t

  #----------------------

#==================================================================================================

class MessageParser 
  constructor : (@slice) ->
  parse : () -> (@parse_packet() while @slice.rem())

  parse_packet : () ->
    {tag, header_len, body, real_packet_len, tag} = (new HeaderParser slice).parse()
    pt = C.packet_tags
    packet = switch tag
      when pt.secret_key, pt.secret_subkey
        require('./packet').KeyMaterial.parse_private_key new SlicerBuffer body
      else
        throw new Error "Unknown packet tag: #{tag}"
    packet.set_tag tag
    packet.set_lengths real_packet_len, header_len
    packet
   
#==================================================================================================

class HeaderParser

  constructor : (@slice) ->
    @body = null
    @real_packet_len = null
    @tag = null
    @len = null
    @header_len = null
    @next = null

  parse : () ->
    @parse_tag_and_len()
    @header_len or= @slice.offset()
    @body or= new SliceBuffer @slice.read_buffer @len
    @real_packet_len or= @len
    @next or= @slice.rest()
    return { @body, @header_len, @real_packet_len, @tag }

  parse_tag_and_len : () ->
    if @slice.len() < 2 or ((c = @slice.read_uint8()) & 0x80) is 0
      throw new Error "This doesn't look like a binary PGP packet"
    if (c & 0x40) is 0 then @parse_tag_and_len_old(c) else @parse_tag_and_len_new(c)

  parse_tag_and_len_old : (c) ->
    @tag = (c & 0x3f) >> 2
    @len = switch (c & 0x03)
      when 0 then @slice.read_uint8()
      when 1 then @slice.read_uint16()
      when 2 then @slice.read_uint32()
      when 3 then @slice.len()

  parse_tag_and_len_new : (c) ->
    @tag = (c & 0x3f)
    @parse_tag_len_new()

  parse_tag_len_new : () -> 
    go = true
    segments = []
    @len = 0
    lastlen = 0
    while go
      go = false
      c = @slice.read_uint8()

      lastlen = if (c < 192) then @slice.read_uint8()
      else if (c is 255) then @slice.read_uint32()
      else if (c < 224) 
        a = (@slice.read_uint8() for i in [0...2])
        ((a[0] - 192) << 8) + (a[1] + 192)
      else
        @header_len or= @slice.offset()
        packet_length = 1 << (c & 0x1f)
        segments.push @slice.read_buffer packet_length 
        go = true
        packet_length

      @len += lastlen
    if segments.length
      segments.push @slice.read_buffer lastlen
      @body = new SliceBuffer Buffer.concat segments
      @len = @body.length
      @real_packet_len = @slice.offset()

#==================================================================================================

exports.Packet = Packet

#==================================================================================================

fs = require 'fs'
await fs.readFile '../../x', defer err, res
console.log res
slice = new SlicerBuffer res
console.log Packet.parse slice

