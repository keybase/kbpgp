
util = require '../util'
{SlicerBuffer} = require './buffer'
C = require('../const').openpgp
{KeyMaterial} = require './keymaterial'
{Signature} = require './signature'
{UserID} = require './userid'
{inspect} = require 'util'

#==================================================================================================

class MessageParser 
  constructor : (@slice) ->
  parse : () -> (@parse_packet() while @slice.rem())
  parse_packet : () -> (new PacketParser @slice).parse()
   
#==================================================================================================

class PacketParser

  #----------------

  constructor : (@slice) ->
    @body = null
    @real_packet_len = null
    @tag = null
    @len = null
    @header_len = null

  #----------------

  parse_header : () ->
    @parse_tag_and_len()
    @header_len or= @slice.offset()
    @body or= new SlicerBuffer @slice.read_buffer @len
    @real_packet_len or= @len
    @slice.unclamp()

  #----------------

  parse : () ->
    @parse_header()
    console.log "got tag -> #{@tag}"
    @parse_body()

  #----------------

  parse_body : () ->
    pt = C.packet_tags
    sb = @body
    packet = switch @tag
      when pt.secret_key, pt.secret_subkey then KeyMaterial.parse_private_key sb
      when pt.public_key                   then KeyMaterial.parse_public_key sb
      when pt.signature                    then Signature.parse sb
      when pt.userid                       then UserID.parse sb
      else throw new Error "Unknown packet tag: #{tag}"
    packet.set_tag @tag
    packet.set_lengths @real_packet_len, @header_len
    packet

  #----------------

  parse_tag_and_len : () ->
    if @slice.len() < 2 or ((c = @slice.read_uint8()) & 0x80) is 0
      throw new Error "This doesn't look like a binary PGP packet"
    if (c & 0x40) is 0 then @parse_tag_and_len_old(c) else @parse_tag_and_len_new(c)

  #----------------

  parse_tag_and_len_old : (c) ->
    @tag = (c & 0x3f) >> 2
    @len = switch (c & 0x03)
      when 0 then @slice.read_uint8()
      when 1 then @slice.read_uint16()
      when 2 then @slice.read_uint32()
      when 3 then @slice.len()

  #----------------

  parse_tag_and_len_new : (c) ->
    @tag = (c & 0x3f)
    @parse_tag_len_new()

  #----------------

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
      @body = new SlicerBuffer Buffer.concat segments
      @len = @body.length
      @real_packet_len = @slice.offset()

#==================================================================================================

exports.parse = parse = (buf) -> 
  (new MessageParser new SlicerBuffer buf).parse()

#==================================================================================================

fs = require 'fs'
await fs.readFile '../../x', defer err, res
console.log err
out = parse res
console.log inspect out, { depth : null }

#==================================================================================================

