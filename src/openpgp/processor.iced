

#==========================================================================================

class KeyBlock

  constructor : (@packets) ->
    # We'll throw away signatures that aren't verified.
    @verified_signatures = []
    @subkeys = []
    @primary = null

  #--------------------

  _extract_keys : () ->
    err = null
    for p,i in @packets when (p.is_key_material() and not err?)
      if not p.is_primary() then @subkeys.push p
      else if @primary? then err = new Error "cannot have 2 primary keys"
      else @primary = p
    err = new Error "No primary key found in keyblock" unless @primary?
    err

  #--------------------

  _check_keys : () -> @_check_primary() or @_check_subkeys()

  #--------------------

  _check_primary : () ->
    console.log @primary.self_sig
    err = if not @primary.self_sig?.type
      new Error "no valid primary key self-signature"
    else if not @primary.self_sig.userid?
      new Error "no valid Userid signed into key"
    else null

  #--------------------

  _check_subkeys : () ->
    subkeys = @subkeys 
    err = null
    @subkeys = []
    for k,i in subkeys when not err?
      if k.is_signed_subkey_of @primary
        @subkeys.push k
      else 
        err = new Error "Could not import subkey #{i}"
    err

  #--------------------

  process : (cb) ->

    err = @_extract_keys()
    await @_verify_sigs defer err unless err?
    err = @_check_keys() unless err?
    cb err

  #--------------------

  _verify_sigs : (cb) ->
    start = 0
    for p,i in @packets
      if p.is_signature()
        p.key = @primary.key
        p.primary = @primary
        data_packets = @packets[start...i]
        await p.verify data_packets, defer tmp
        if tmp?
          console.log "Error in signature verification: #{tmp.toString()}"
          err = tmp
          # discard the signature, see the above comment...
        else
          @verified_signatures.push p
        start = i + 1
    cb err

  #--------------------

#==========================================================================================

exports.KeyBlock = KeyBlock

#==========================================================================================
