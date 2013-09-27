
C = require('./const').openpgp
algos = require('triplesec').hash

#================================================================

make_hasher = (klass, name, type) -> 
  if klass?
    f = (x) -> (new klass).bufhash x
    f.type = type
    f.algname = name
    f.output_length = klass.blockSize
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

#================================================================

