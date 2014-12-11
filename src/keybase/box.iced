
#=================================================================================

console.log "+ INC box"
encode = require './encode'
{asyncify,akatch} = require '../util'
{make_esc} = require 'iced-error'
konst = require '../const'
{alloc} = require './packet/alloc'
{Signature} = require './packet/signature'
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
    await akatch ( () -> encode.unseal buf), esc defer rawobj

  await asyncify alloc(rawobj), esc defer packet
  await packet.unbox esc defer res

  cb null, res

#=================================================================================

exports.box = ({msg, sign_with}, cb) ->
  esc = make_esc cb, "box"
  await Signature.box { km : sign_with, payload : msg }, esc defer packet
  packed = packet.frame_packet()
  sealed = encode.seal { obj : packed, dohash : false }
  armored = sealed.toString('base64')
  cb null, armored

#=================================================================================
