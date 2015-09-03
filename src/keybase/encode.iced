K = require('../const').kb
{alloc,SHA256} = require '../hash'
purepack = require 'purepack'
{katch,obj_extract,bufeq_secure} = require '../util'

#=================================================================================

null_hash = new Buffer(0)

pack   = (x) -> purepack.pack   x, { sort_keys : true }
unpack = (x) -> purepack.unpack x, { strict : true }

#=================================================================================

seal = ({obj, dohash}) ->
  hasher = SHA256
  oo =
    version : K.versions.V1
    tag: obj.tag
    body : obj.body
  if dohash
    oo.hash =
      type : hasher.type
      value : null_hash
    packed = pack oo
    oo.hash.value = hasher packed
  pack oo

#=================================================================================

read_base64 = (raw) ->
  parts = (raw.split /\s+/).join('')
  new Buffer parts, 'base64'

#=================================================================================

unseal = (buf) ->
  oo = unpack buf # throws an error if there's a problem
  if (hv = oo?.hash?.value)?
    oo.hash.value = null_hash
    hasher = alloc (t = oo.hash.type)
    throw new Error "unknown hash algo: #{t}" unless hasher?
    h = hasher pack oo
    throw new Error "hash mismatch" unless bufeq_secure(h, hv)
    throw new Error "unknown version" unless oo.version is K.versions.V1
  obj_extract oo, [ 'tag', 'body' ]

#=================================================================================

exports.seal = seal
exports.pack = pack
exports.unseal = unseal
exports.unpack = unpack
exports.read_base64 = read_base64
