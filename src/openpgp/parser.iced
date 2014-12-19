
util = require '../util'
{SlicerBuffer} = require './buffer'
C = require('../const').openpgp
{KeyMaterial} = require './packet/keymaterial'
{Signature} = require './packet/signature'
{SEIPD,PKESK} = require './packet/sess'
{UserID} = require './packet/userid'
{UserAttribute} = require './packet/user_attribute'
{Compressed} = require './packet/compressed'
{Generic} = require './packet/generic'
{OnePassSignature} = require './packet/one_pass_sig'
{Literal} = require './packet/literal'
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
    ret = @parse_body()
    ret

  #----------------

  parse_body : () ->
    pt = C.packet_tags
    sb = @body
    raw = sb.peek_rest_to_buffer()
    packet = switch @tag
      when pt.PKESK          then PKESK.parse sb
      when pt.one_pass_sig   then OnePassSignature.parse sb
      when pt.secret_key     then KeyMaterial.parse_private_key sb, { subkey : false }
      when pt.secret_subkey  then KeyMaterial.parse_private_key sb, { subkey : true }
      when pt.public_key     then KeyMaterial.parse_public_key sb,  { subkey : false }
      when pt.public_subkey  then KeyMaterial.parse_public_key sb,  { subkey : true }
      when pt.signature      then Signature.parse sb
      when pt.userid         then UserID.parse sb
      when pt.user_attribute then UserAttribute.parse sb
      when pt.SEIPD          then SEIPD.parse sb
      when pt.literal        then Literal.parse sb
      when pt.compressed     then Compressed.parse sb
      else                   new Generic @tag, sb # throw new Error "Unknown packet tag: #{@tag}"
    packet.set { @tag, @real_packet_len, @header_len, raw }
    packet

  #----------------

  parse_tag_and_len : () ->
    if @slice.len() < 2 or ((c = @slice.read_uint8()) & 0x80) is 0
      throw new Error "This doesn't look like a binary PGP packet (c=#{c})"
    if (c & 0x40) is 0 then @parse_tag_and_len_old(c) else @parse_tag_and_len_new(c)

  #----------------

  parse_tag_and_len_old : (c) ->
    @tag = (c & 0x3f) >> 2
    @len = switch (c & 0x03)
      when 0 then @slice.read_uint8()
      when 1 then @slice.read_uint16()
      when 2 then @slice.read_uint32()
      when 3 then @slice.rem()

  #----------------

  parse_tag_and_len_new : (c) ->
    @tag = (c & 0x3f)
    ret = @parse_tag_len_new()
    ret

  #----------------

  parse_tag_len_new : () ->
    go = true
    segments = []
    @len = 0
    lastlen = 0
    while go
      go = false
      c = @slice.read_uint8()

      lastlen = if (c < 192) then c
      else if (c is 255) then @slice.read_uint32()
      else if (c < 224)
        d = @slice.read_uint8()
        ((c - 192) << 8) + (d + 192)
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
  util.katch () ->
    (new MessageParser new SlicerBuffer buf).parse()

#==================================================================================================

