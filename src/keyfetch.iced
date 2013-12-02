
#=================================================================================

# A base KeyFetch class -- subclass to implement the fetching of keys.
class KeyFetcher
  constructor : () ->

  # @param {Vec<Buffer>} ids Ids to look for, any will do.
  # @param {number} ops The operations we need, represented as a compressed
  #   bitmask of operations from kbpgp.const.ops
  # @param {callback} cb The cb to call back when done
  fetch : (ids, ops, cb) -> cb new Error "not implemented"

#=================================================================================

exports.KeyFetcher = KeyFetcher

#=================================================================================

