
{sign,verfiy} = require '../sign'

#=================================================================================

class Base
  constructor : ({@type,@key}) ->

  #------

  sign : ({asp}, cb) ->
    body = @_v_body()
    await sign { @key, @type, body }, defer err, sig
    cb err, sig

  #------

  sign_to_packet : ({asp}, cb) ->
    await @sign { asp }, defer err, sig
    unless err?
      ret = new Packet.

#=================================================================================

exports.Base = Base

#=================================================================================

