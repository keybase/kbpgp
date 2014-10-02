{KeyFetcher} = require './keyfetch'

#=================================================================================

hexkid = (k) -> k.toString('hex')

#=================================================================================

class PgpKeyRing extends KeyFetcher

  #-------------

  constructor : () ->
    @_keys = {}
    @_kms = {}

  #-------------

  add_key_manager : (km) ->
    keys = km.export_pgp_keys_to_keyring()
    for k in keys
      kid = hexkid(k.key_material.get_key_id())
      @_keys[kid] = k
      @_kms[kid] = km

  #-------------

  fetch : (key_ids, ops, cb) ->
    key_material = err = obj = null
    key_ids = (hexkid(k) for k in key_ids)
    km = null
    for id,i in key_ids
      k = @_keys[id]
      if k?.key?.can_perform ops
        ret_i = i
        km = @_kms[id]
        break
    unless km?
      err = new Error "key not found: #{JSON.stringify key_ids}"
    cb err, km, ret_i

  #-------------

  # Pick the best key to fill the flags asked for by the flags.
  # See C.openpgp.key_flags for ideas of what the flags might be.
  find_best_key : ({key_id, flags}, cb) ->
    if not (km = @_kms[(kid = hexkid key_id)])?
      err = new Error "Could not find key for fingerprint #{kid}"
    else if not (key = km.find_best_pgp_key flags)?
      err = new Error "no matching key for flags: #{flags}"
    cb err, key

  #-------------

  lookup : (key_id) -> @_keys[hexkid key_id]

#=================================================================================

exports.PgpKeyRing = PgpKeyRing
exports.KeyRing = PgpKeyRing

#=================================================================================
