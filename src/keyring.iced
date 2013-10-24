

#=================================================================================

class PgpKeyRing

  constructor : () ->
    @_keys = {}

  add_key_manager : (km) ->
    keys = km.export_pgp_keys_to_keyring()
    for k in keys
      @_keys[k.key_material.get_key_id()] = k

  lookup : (key_id) -> @_keys[key_id]

#=================================================================================

exports.PgpKeyRing = PgpKeyRing

#=================================================================================
