
{unbox} = require './encode'
{Packet} = require './packet/base'
{akatch} = require '../util'
{make_esc} = require 'iced-utils'

#=================================================================================

exports.parse = (raw, cb) ->
  esc = make_esc cb, "parse"
  await akatch ( () -> unbox raw), esc defer obj
  await asyncify Packet.alloc(obj), esc defer pack
  cb null, pack

#=================================================================================

