
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
zlib = require 'zlib'

#=================================================================================

fake_zip_inflate = (buf, cb) ->
  buf = Buffer.concat [ new Buffer([0x78,0x9c]), buf ]
  await zlib.inflate buf, defer err, ret
  cb err, ret

#=================================================================================

# 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
class Compressed extends Packet

  constructor : ( {@algo, @compressed}) ->

  @parse : (slice) -> (new CompressionParser slice).parse()

  inflate : (cb) ->
    err = ret = null
    switch @algo
      when C.compression.none then ret = @compressed
      when C.compression.zlib
        await zlib.inflate @compressed, defer err, ret
      when C.compression.zip
        await fake_zip_inflate @compressed, defer err, ret
      else
        err = new Error "no known inflation -- algo: #{@algo}"
    cb err, ret

#=================================================================================

class CompressionParser 

  constructor : (@slice) ->

  #  The body of this packet consists of:
  #
  #   - A one-octet version number.  The only currently defined value is 1.
  #   - Encrypted data, the output of the selected symmetric-key cipher
  #     operating in Cipher Feedback mode with shift amount equal to the
  #     block size of the cipher (CFB-n where n is the block size).
  parse : () ->
    algo = @slice.read_uint8()
    compressed = @slice.consume_rest_to_buffer()
    new Compressed { algo, compressed }

#=================================================================================

exports.Compressed = Compressed

#=================================================================================
