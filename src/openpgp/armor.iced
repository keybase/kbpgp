
{katch,bufeq_fast,uint_to_buffer} = require '../util'
C = require '../const'
Ch = require '../header'
{armor} = require('pgp-utils')
xbt = require '../xbt'

#=========================================================================

MT = C.openpgp.message_types

type_table = 
  "PUBLIC KEY BLOCK"  : MT.public_key
  "PRIVATE KEY BLOCK" : MT.private_key
  "SIGNATURE"         : MT.signature
  "MESSAGE"           : MT.generic

r_type_table = {}
for k,v of type_table
  r_type_table[v] = k

#=========================================================================

exports.encode = (type, data) ->
  mt = C.openpgp.message_types
  if not (type = r_type_table[type])?
    throw new Error "Cannot encode tag type #{type}"
  return armor.encode Ch, type, data

#=========================================================================

class Parser extends armor.Parser

  parse_type : () ->
    if not(@ret.type = type_table[@type])?
      throw new Error "Unknown message type: #{@type}"
    else if (@ret.type is MT.clearsign) and not @ret.clearsign
      throw new Error "Signed message, but not clear-signed"
    @ret.fields.type = @type

#=========================================================================

exports.XbtArmorer = class XbtArmorer extends xbt.InBlocker

  constructor : ({type}) ->
    @_enc = new armor.Encoder Ch
    unless (type = r_type_table[type])?
      @_err = new Error "Bad type"
    @_frame = @_enc.frame type
    @_out_width = 64                   # 64-base64-encoded characters
    @_in_width = (@_out_width / 4) * 3 # in input characters
    super @_in_width
    @_crc = null

  _v_init : (cb) ->
    unless @_err?
      hdr = @_frame.begin.concat(@_enc.header(), "\n")
      buf = new Buffer hdr, 'utf8'
    cb @_err, buf

  _v_inblock_chunk : ({data, eof}, cb) ->
    strings = []
    if data?
      strings.push (data.toString('base64') + "\n")
      @_crc = armor.compute_crc24 data, @_crc
    if eof
      chksum = "=" + uint_to_buffer(32, @_crc)[1...4].toString('base64')
      strings.push chksum + "\n"
      strings.push @_frame.end
    buf = new Buffer strings.join(""), "utf8"
    cb null, buf

#=========================================================================

exports.XbtDemux = class XbtDemux extends xbt.Demux

  constructor : (mt) ->
    @_prefix = "----- BEGIN PGP"
    super

  peek_bytes : () -> @_prefix.length

  _demux : ({data, eof}, cb) ->
    if data? and data.toString('utf8') is @_prefix
      ret = new XbtDearmorer()
    else
      ret = new xbt.Passthrough()
    cb null, ret, data

#=========================================================================

class XbtTokenizer extends xbt.Gets

  constructor : () ->
    super { maxline : 4096, mod : 4 }

  _v_line_chunk : ({data, newline, eof}, cb) ->
    tok = if not data? then null
    else 
      s = data.toString('utf8')
      if (m = s.match /^-{5} (BEGIN|END) PGP (\w+) -{5}$/)?
        { type : 'frame', begin : (m[1] is 'BEGIN'), msg_type : m[2] }
      else if (m = s.match /^(\w+): (.*)$/)?
        { type : 'comment', name : m[1], value : m[2] }
      else if (m = s.match /^=(\w+)$/ )
        { type : 'checksum', value : m[1] }
      else if data.length is 0
        { type : 'empty' }
      else
        { type :'data', value : s }
    if tok? or eof
      await @_v_token_chunk { tok, eof }, defer err, out
    cb err, out

#=========================================================================

exports.XbtDearmorer = class XbtDearmorer extends XbtTokenizer

  constructor : () ->
    @_state = 0
    @_msg_type = null
    @_comments = []
    @_crc24 = null

  _v_line_chunk : ( {tok, eof}, cb) ->
    err = out = null
    if tok?
      switch @_state
        when 0
          if (tok.type is 'frame') and (tok.begin)
            @_msg_type = tok.msg_type
            @_state++
          else
            err = new Error "Failed to get valid '----- BEGIN PGP ...' block "
        when 1 
          if (tok.type is 'comment')
            @_comments.push [ tok.name, tok.value ]
          else if (tok.type is 'empty')
            @_state++
          else
            err = new Error "Got bad field in comment region"
        when 2
          if (tok.type is 'data')
            out = new Buffer tok.value, 'base64'
            @_crc24 = armor.compute_crc24 out, @_crc24
          else if (tok.type is 'checksum')
            @_checksum = new Buffer tok.value, 'base64'
            @_state++
          else
            err = new Error "Got bad data on #{@_lineno}"
        when 3
          if (tok.type isnt 'frame') or (tok.begin)
            err = new Error "On line #{@_lineno}: expected a END PGP closer"
          else if tok.msg_type isnt @_msg_type
            err = new Error "Opened type #{@_msg_type} != #{tok.msg_type}"
          else
            @_state++
        else
          if tok.type isnt 'empty'
            err = new Error "Should not still be getting data in end state"

    if not eof then # noop
    else if @_state isnt 4
      err = new Error "EOF before close of message"
    else
      chksum = uint_to_buffer(32, @_crc24)[1...4].toString('base64')
      if chksum isnt @_checksum
        err = new Error "Checksum failure: #{chksum} != #{@_checksum}"

    cb err, out

#=========================================================================

exports.Message = armor.Message

#=========================================================================

#
# Decode armor64-ed data, including header framing, checksums, etc.
#
# @param {String} data The data to decode. Alternatively, you can provide
#   a Buffer, and we'll output utf8 string out of it.
# @return {Array<{Error},{Buffer}>} And error or a buffer if success.
#
exports.decode = decode = (data) -> katch () -> (new Parser data).parse()
exports.mdecode = decode = (data) -> katch () -> (new Parser data).mparse()

#=========================================================================


