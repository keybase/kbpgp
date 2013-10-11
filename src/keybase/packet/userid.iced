K = require('../../const').kb
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

