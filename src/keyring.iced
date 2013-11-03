{KeyFetcher} = require './keyfetch'

#=================================================================================

class PgpKeyRing extends KeyFetcher

  constructor : () ->
    @_keys = {}

  add_key_manager : (km) ->
    keys = km.export_pgp_keys_to_keyring()
    for k in keys
      console.log "I " + k.key_material.get_key_id().toString('base64')
      @_keys[k.key_material.get_key_id().toString('base64')] = k

  fetch : (key_ids, ops, cb) -> 
    ret = null
    key_ids = (k.toString('base64') for k in key_ids)
    for id,i in key_ids when not ret?
      k = @_keys[id]
      if k?.key?.can_perform ops
        ret_i = i
        ret = k
    err = if ret? then null else new Error "key not found: #{JSON.stringify key_ids}"
    cb err, ret, ret_i

  lookup : (key_id) -> @_keys[key_id]

#=================================================================================

exports.PgpKeyRing = PgpKeyRing

#=================================================================================
