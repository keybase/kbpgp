
#=================================================================================

# A base KeyFetch class -- subclass to implement the fetching of keys.
class KeyFetcher
  constructor : () ->

  # @param {Vec<Buffer>} ids Ids to look for, any will do.
  # @param {number} ops The operations we need, represented as a compressed
  #   bitmask of operations from kbpgp.const.ops
  # @param {callback} cb The cb to call back when done; if successful,
  #   with a KeyFetched object
  fetch : (ids, ops, cb) -> cb new Error "not implemented"

#=================================================================================

exports.KeyFetcher = KeyFetcher

#=================================================================================

exports.KeyFetched = class KeyFetched

  # @param {BaseKeyPair} pair --- A keypair an RSA. ECHD or ECSDA.
  #   Something we can call the following methods on:
  #       - decrypt_and_unpad
  #       - pad_and_encrypt
  #       - verify_unpad_and_check_hash
  #       - pad_and_sign 
  # @param {Buffer} fingerprint --- the PGP-style fingerprint generated over
  #   the master or subkey in question
  constructor : ({@pair, @fingerprint}) ->

  decrypt_and_unpad : (ciphertext, cb) ->
    @pair.decrypt_and_unpad ciphertext, { @fingerprint }, cb
  pad_and_encrypt : (plaintext, cb) ->
    @pair.decrypt_and_unpad plaintext, { @fingerprint }, cb

  pad_and_sign : (data, params, cb) -> @pair.pad_and_sign data, params, cb
  verify_unpad_and_check_hash : (params, cb) -> @pair.verify_unpad_and_check_hash params, cb

#=================================================================================

