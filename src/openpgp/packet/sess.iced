
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'

#=================================================================================

# 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
class PKESK extends Packet

  constructor : ( {@crypto_type, @key_id, @ekey }) ->

  @parse : (slice) -> (new PKESK_Parser slice).parse()


#=================================================================================

# 5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
class SEIPD extends Packet

  constructor : ( { @ciphertext } ) ->

  @parse : (slice) -> (new SEIPD_Parser slice).parse()

#=================================================================================

class SEIPD_Parser 

  constructor : (@slice) ->

  #  The body of this packet consists of:
  #
  #   - A one-octet version number.  The only currently defined value is 1.
  #   - Encrypted data, the output of the selected symmetric-key cipher
  #     operating in Cipher Feedback mode with shift amount equal to the
  #     block size of the cipher (CFB-n where n is the block size).
  parse : () ->
    throw new Error "Unknown SEIPD version #{v}" unless (v = @slice.read_uint8()) is C.versions.SEIPD
    ciphertext = @slice.consume_rest_to_buffer()
    new SEIPD { ciphertext } 

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
    key_id = @slice.read_buffer 8
    crypto_type = @slice.read_uint8()
    klass = asymmetric.get_class crypto_type
    ekey = klass.parse_output @slice.consume_rest_to_buffer() 
    new PKESK { crypto_type, key_id, ekey }

#=================================================================================

exports.SEIPD = SEIPD
exports.PKESK = PKESK

#=================================================================================
