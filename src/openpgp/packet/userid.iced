
C = require('../../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{uint_to_buffer,calc_checksum} = require '../util'
{encrypt} = require '../cfb'
{Packet} = require './base'

#=================================================================================

class UserID extends Packet

  # @param {Buffer} userid The utf8-buffer withstring reprensentation of the UserID
  constructor : (@userid) -> super()

  #--------------------------

  utf8  : () -> @userid
  write : () -> @frame_packet C.packet_tags.userid, @userid

  #--------------------------

  @parse : (slice) -> new UserID slice.consume_rest_to_buffer() 

  #--------------------------

  to_signature_payload : () ->

    # RFC 4880 5.2.4 Computing Signatures Over a Key
    Buffer.concat [
      new Buffer([ C.signatures.userid ]),
      uint_to_buffer(32, @userid.length),
      @userid
    ]
    
  #--------------------------
  
#=================================================================================

exports.UserID = UserID

#=================================================================================
