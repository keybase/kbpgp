
{PublicKey,PrivateKey} = require './key'
{unbox} = require '../encode'
K = require('../const').kb

#=================================================================================

#
# Parse an incoming raw byte sequence, and make a message out of it.
#
# @param {Buffer} raw The raw byte sequence
#
# @return{[Error,msg.Base]} A pair, with an error on error, or a non-null
#   object of base type msg.Base on success.
#
parse = (raw) ->
  ret = null
  [err, res] = katch () -> unbox raw
  err = new Error "cannot unbox message" if not err? and (res.genre isnt K.genres.message)
  unless err?
    packets = res.obj
    ret = switch res.type
      when K.message_types.public_key then new PublicKey { packets }  
      when K.message_types.private_key then new PrivateKey { packets }
      else 
        err = new Error "Cannot decode message type #{res.type}"
        null
  [err, ret]

#=================================================================================

exports.parse = parse

#=================================================================================

