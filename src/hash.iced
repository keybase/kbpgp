
C = require('./const').openpgp
triplesec = require 'triplesec'
{WordArray} = triplesec
algos = triplesec.hash

#================================================================

make_hasher = (klass, name, type) -> () ->
  _o = new klass
  ret = (x) -> _o.bufhash(x)
  ret.update = (x) -> 
    _o.update(WordArray.from_buffer(x)) if x?
    ret
  ret.type = type
  ret.algname = name
  ret.output_length = klass.output_size
  ret.klass = klass
  ret

  ret = (buf) 

  if klass?
    f = (x) -> (new klass).bufhash x
    decorate(f, klass, name, type)
  else null

make_streamer = (klass, name, type) -> () ->
  obj = new klass
  ret = (buf) -> obj.finalize(if buf? then wordarray.from_buffer(buf) else null).to_buffer()
  ret.update = (buf) -> if buf? then obj.update(wordarray.from_buffer(buf)) else @
  decorate(ret, klass, name, type)

_lookup = {}
exports.streamers = streamers = {}
for k,v of C.hash_algorithms
  _lookup[v] = k
  exports[k] = make_hasher algos[k], k, v
  streamers[k] = make_stream algos[k], k, v

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

