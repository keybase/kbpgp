
{Packet} = require './base'
C = require('../../const').openpgp

#=================================================================================

class PublicKeyEncryptedSessionKey extends Packet

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
    throw new Error "Unknown PKESK version: #{v}" unless (v = @slice.read_uint8()) is C.version.PKESK
    fingerprint = @slice.read_buffer 8
    typ = slice.read_uint8()


#=================================================================================

