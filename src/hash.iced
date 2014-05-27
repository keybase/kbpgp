
C = require('./const').openpgp
triplesec = require 'triplesec'
{WordArray} = triplesec
algos = triplesec.hash

#================================================================

# take a function f, and "decorate it" with all of the nice
# properties we expect
decorate = (f, klass, name, type) ->
  f.type = type
  f.algname = name
  f.output_length = klass.output_size
  f.klass = klass
  f 

#--------------------

# By default, hashing is one-shot. You call the function once, on a giant
# buffer, and it returns the hash.
make_hasher = (klass, name, type) -> 
  if klass?
    f = (x) -> (new klass).bufhash x
    decorate(f, klass, name, type)
  else null

#--------------------

# A streamer can be "updated" multiple times, but if called directly,
# will make a last-ditch effort (and therefore is duck-type compatible
# with the default hasher above).
make_streamer = (klass, name, type) -> () ->
  obj = new klass

  # Clone in case we need to hash ourselves multiple times...
  ret = (buf) -> obj.clone().finalize(if buf? then WordArray.from_buffer(buf) else null).to_buffer()
  
  ret.update = (buf) -> 
    obj.update(WordArray.from_buffer(buf)) if buf?
    @
  decorate(ret, klass, name, type)

#--------------------

_lookup = {}
exports.streamers = streamers = {}
for k,v of C.hash_algorithms
  _lookup[v] = k
  exports[k] = make_hasher algos[k], k, v
  streamers[k] = make_streamer algos[k], k, v

#--------------------

exports.alloc = alloc = (typ) ->
  ret = null
  name = _lookup[typ]
  klass = algos[name] if name?
  ret = make_hasher(klass,name,typ) if klass?
  ret

#--------------------

exports.alloc_or_throw = alloc_or_throw = (typ) ->
  ret = alloc typ
  throw new Error "unknown hash type: #{typ}" unless ret
  ret

#================================================================

