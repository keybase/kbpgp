
#=================================================================================

# A base KeyFetch class -- subclass to implement the fetching of keys.
class KeyFetcher
  constructor : () ->
  fetch : (ids, ops, cb) -> cb new Error "not implemented"

#=================================================================================

exports.KeyFetcher = KeyFetcher

#=================================================================================

