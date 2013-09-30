K = require('../const').kb
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{calc_checksum} = require '../util'
{encrypt} = require '../cfb'
{Packet} = require './base'

#=================================================================================

class UserID extends Packet

  constructor : (@uid) ->
    super()

  #--------------------------

  to_json : () -> { userid : @uid }

  #--------------------------

  write : () ->
    @frame_packet K.packet_tags.userid, @to_json()
    
#=================================================================================

