
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


