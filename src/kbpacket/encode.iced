K = require('../const').kb
{SHA512} = require '../hash'
purepack = require 'purepack'

#=================================================================================

null_hash = new Buffer(0)

pack = (x) ->
  purepack.pack x, 'buffer', { sort_keys : true }

bencode = (type, obj) ->
  oo = 
    version : K.versions.V1 
    type : type
    body : obj
    hash : 
      type : SHA512.type
      value : null_hash
  packed = pack oo
  oo.hash.value = SHA512 packed
  pack oo

#=================================================================================

exports.bencode = bencode
exports.pack = pack
