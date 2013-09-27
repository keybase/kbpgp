
C = require('../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{calc_checksum} = require '../util'
{encrypt} = require '../cfb'
{Packet} = require './base'

#=================================================================================

class KeyMaterial extends Packet

  constructor : (@userid) ->
    super()

  #--------------------------

  write : () ->
    body = new Buffer @userid, 'utf8' 
    @_write_public bufs, timepacket
    body = Buffer.concat bufs
    @frame_packet C.packet_tags.userid, body

  #--------------------------
  
#=================================================================================

