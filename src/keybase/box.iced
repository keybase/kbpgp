
#=================================================================================

console.log "+ INC box"
encode = require './encode'
{asyncify,akatch} = require '../util'
{make_esc} = require 'iced-error'
konst = require '../const'
{alloc} = require './packet/alloc'
{sign} = require './packet/signature'
K = konst.kb
C = konst.openpgp
console.log "- INC box"

#=================================================================================

exports.unbox = ({armored,rawobj}, cb) ->
  esc = make_esc cb, "unbox"

  if not armored? and not rawobj?
    await athrow (new Error "need either 'armored' or 'rawobj'"), esc defer()

  if armored?
    buf = new Buffer armored, 'base64'
    await akatch ( () -> encode.unbox buf), esc defer rawobj

  await asyncify alloc(rawobj), esc defer packet
  await packet.unbox esc defer res

  cb null, res

#=================================================================================

exports.box = ({msg, sign_with}, cb) ->
  esc = make_esc cb, "box"
  await sign { km : sign_with, payload : msg }, esc defer packet
  armored = packet.frame_packet_armored { dohash : false }
  cb null, armored

#=================================================================================
