
C = require('../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{calc_checksum} = require '../util'
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
  
#=================================================================================

exports.UserID = UserID

#=================================================================================
