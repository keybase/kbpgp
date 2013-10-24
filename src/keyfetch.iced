
#=================================================================================

# A base KeyFetch class -- subclass to implement the fetching of keys.
class KeyFetch
  constructor : () ->
  fetch : (ids, ops, cb) -> cb new Error "not implemented"

#=================================================================================

