
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
zlib = require 'zlib-browserify'

#=================================================================================

# 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
class Compressed extends Packet

  constructor : ( {@algo, @compressed}) ->

  @parse : (slice) -> (new CompressionParser slice).parse()

  inflate : (cb) ->
    err = ret = null
    if @algo is 2
      await zlib.inflate @compressed, defer err, ret
    else
      err = new Error "no known inflation"
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
