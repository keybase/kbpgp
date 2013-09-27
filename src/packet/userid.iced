
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

  # @param {String} userid The string reprensentation of the UserID
  constructor : (userid) ->
    super()
    @userid = new Buffer userid, 'utf8'

  #--------------------------

  write : () ->
    @frame_packet C.packet_tags.userid, @userid

  #--------------------------
  
#=================================================================================

exports.UserID = UserID

#=================================================================================
