K = require('../const').kb
{alloc,SHA256} = require '../hash'
purepack = require 'purepack'
{bufeq_secure} = require '../util'

#=================================================================================

null_hash = new Buffer(0)

pack   = (x) -> purepack.pack   x, 'buffer', { sort_keys : true, byte_arrays : true }
unpack = (x) -> purepack.unpack x, 'buffer'

#=================================================================================

bencode = (type, obj) ->
  hasher = SHA256
  oo = 
    version : K.versions.V1 
    type : type
    body : obj
    hash : 
      type : hasher.type
      value : null_hash
  packed = pack oo
  oo.hash.value = hasher packed
  pack oo

#=================================================================================

bdecode = (buf) ->
  ret = null
  err = null
  try
    [err,oo] = unpack buf
    throw err if err?
    throw new Error "missing obj.hash.value" unless (hv = oo?.hash?.value)?
    oo.hash.value = null_hash
    hasher = alloc (t = oo.hash.type)
    throw new Error "unknown hash algo: #{t}" unless hasher?
    h = hasher pack oo
    throw new Error "hash mismatch" unless bufeq_secure(h, hv)
    throw new Error "unknown version" unless oo.version is K.versions.V1
    ret = [ oo.type, oo.body ] 
  catch e
    err = e
  [err, ret]

#=================================================================================

exports.bencode = bencode
exports.pack = pack
exports.unpack = unpack
exports.bdecode = bdecode
