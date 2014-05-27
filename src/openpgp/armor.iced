
{katch,bufeq_fast,uint_to_buffer} = require '../util'
C = require '../const'
Ch = require '../header'
{armor} = require('pgp-utils')

#=========================================================================

exports.encode = (type, data) ->
  mt = C.openpgp.message_types
  type = switch type
    when mt.public_key  then "PUBLIC KEY BLOCK"
    when mt.private_key then "PRIVATE KEY BLOCK"
    when mt.signature   then "SIGNATURE"
    when mt.generic     then "MESSAGE"
    else
      throw new Error "Cannot encode tag type #{type}"
  return armor.encode Ch, type, data

#=========================================================================

class Parser extends armor.Parser

  parse_type : () ->
    mt = C.openpgp.message_types
    @ret.type = switch @type
      when "PUBLIC KEY BLOCK" then mt.public_key
      when "PRIVATE KEY BLOCK" then mt.private_key
      when "SIGNED MESSAGE"
        if @ret.clearsign then mt.clearsign
        else throw new Error "Signed message, but not clear-signed"
      when "SIGNATURE" then mt.signature
      when "MESSAGE" then mt.generic
      else throw new Error "Unknown message type: #{@type}"
    @ret.fields.type = @type

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
