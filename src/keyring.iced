{KeyFetcher} = require './keyfetch'

#=================================================================================

class PgpKeyRing extends KeyFetcher

  constructor : () ->
    @_keys = {}

  add_key_manager : (km) ->
    keys = km.export_pgp_keys_to_keyring()
    for k in keys
      @_keys[k.key_material.get_key_id()] = k

  fetch : (key_ids, ops, cb) -> 
    ret = null
    for id,i in key_ids when not ret?
      k = @_keys[id]
      if k?.key?.can_peform ops
        ret_i = i
        ret = k
    err = if ret? then null else new Error "key not found"
    cb err, ret, ret_i

#=================================================================================

exports.PgpKeyRing = PgpKeyRing

#=================================================================================
