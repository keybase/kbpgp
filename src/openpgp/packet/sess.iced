
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'

#=================================================================================

# 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
class PKESK extends Packet

  constructor : ( {@crypto_type, @fingerprint, @ekey }) ->

  @parse : (slice) -> (new PKESK_Parser(slice)).parse()


#=================================================================================

class PKESK_Parser

  constructor : (@slice) ->

  # 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
  # Format:
  #    - 1 byte version ( == 3)
  #    - 8 byte Key Fingerprint
  #    - 1 byte CryptoSystem type
  #    - variable length MPIs
  #   
  parse : () ->
    throw new Error "Unknown PKESK version: #{v}" unless (v = @slice.read_uint8()) is C.versions.PKESK
    fingerprint = @slice.read_buffer 8
    crypto_type = @slice.read_uint8()
    klass = asymmetric.get_class crypto_type
    ekey = klass.parse_output @slice.consume_rest_to_buffer() 
    new PKESK { crypto_type, fingerprint, ekey }

#=================================================================================

exports.PKESK = PKESK

#=================================================================================
