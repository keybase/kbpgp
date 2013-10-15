
{box,unbox} = require './encode'
K = require('../const').kb

#=================================================================================

class Base

  #-------------

  constructor : ( {@type, @packets} ) ->

  #-------------
  
  box : -> box { genre : K.genres.message, @type, obj : @packets } 

  #-------------
  
  @unbox : (raw) ->
    ret = null
    [err, res] = unbox raw
    err = new Error "cannot unbox message" if not err? and (res.genre isnt K.genres.message)
    ret = new Message { type : res.type, packets : res.obj } unless err?
    [err, ret]

#=================================================================================

exports.Base = Base

#=================================================================================

