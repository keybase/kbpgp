
C = require('./const').openpgp
algos = require('triplesec').hash

#================================================================

make_hasher = (klass, name, type) -> 
  if klass?
    f = (x) -> (new klass).bufhash x
    f.type = type
    f.algname = name
    f.output_length = klass.output_size
    f
  else null

_lookup = {}
for k,v of C.hash_algorithms
  _lookup[v] = k
  exports[k] = make_hasher algos[k], k, v

exports.alloc = alloc = (typ) ->
  ret = null
  name = _lookup[typ]
  klass = algos[name] if name?
  ret = make_hasher(klass,name,typ) if klass?
  ret

exports.alloc_or_throw = alloc_or_throw = (typ) ->
  ret = alloc typ
  throw new Error "unknown hash type: #{typ}" unless ret
  ret

#================================================================

