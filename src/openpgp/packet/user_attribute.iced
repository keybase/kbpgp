
C = require('../../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{bufferify,uint_to_buffer} = require '../../util'
{encrypt} = require '../cfb'
{Packet} = require './base'
{parse} = require('pgp-utils').userid

#=================================================================================

class UserAttribute extends Packet

  # @param {Buffer} data The data read from the packet
  constructor : (@data) -> 
    super()

  #--------------------------

  write : () -> @frame_packet C.packet_tags.user_attribute, @data

  #--------------------------

  @parse : (slice) -> new UserAttribute slice.consume_rest_to_buffer() 

  #--------------------------

  to_user_attribute : () -> @

  #--------------------------

  to_signature_payload : () ->

    # RFC 4880 5.12 We can treat the user attribute packet as a userID
    # packet, but with opaque data.
    Buffer.concat [
      new Buffer([ C.signatures.user_attribute ]),
      uint_to_buffer(32, @data.length),
      @data
    ]
    
  #--------------------------

#=================================================================================

exports.UserAttribute = UserAttribute

#=================================================================================
