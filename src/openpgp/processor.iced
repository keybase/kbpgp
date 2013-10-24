
{make_esc} = require 'iced-error'
{OPS} = require '../keyfetch'

#==========================================================================================

class KeyBlock

  constructor : (@packets) ->
    # We'll throw away signatures that aren't verified.
    @verified_signatures = []
    @subkeys = []
    @primary = null
    @userid = null

  #--------------------

  to_obj : () -> return { @subkeys, @primary, @userid }

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
    err = if not @primary.self_sig?.type
      new Error "no valid primary key self-signature"
    else if not (@userid = @primary.self_sig.userid)?
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

class Message 

  #---------

  constructor : (@packets, @key_fetch) ->
    @literals = []
    @enc_data_packet = null

  #---------

  _decrypt : (cb) ->
    await @key.decrypt_and_unpad @enc_data_packet

  #---------

  _get_session_key : (cb) ->
    key_ids = []
    esk_packets = []
    err = null

    key_ids = while @packets.length and (p = @packets[0].to_esk_packet())
      esk_packets.push p
      @packets.pop()
      p.get_key_id()

    if key_ids.length 
      enc = true      
      await @key_fetch.fetch key_ids, [ OPS.decrypt ], defer err, obj, index
      unless err?
        packet = esk_packets[index]
        await obj.key.decrypt_and_unpad packet.ekey.y, defer err, sesskey
    else
      enc = false

    cb err, enc, sesskey

  #---------

  _find_encrypted_data : (cb) ->
    err = ret = null
    if @packets.length and (ret = @packets[0].to_enc_data_packet())
      @packets.pop()
    else err = new Error "Could not encrypted data packet"
    cb err, ret

  #---------

  _decrypt_with_session_key : (sesskey, edat, cb) ->
    err = null
    try
      cipher = import_key_pgp sesskey
      ret = decrypt { cipher, ciphertext : edat.ciphertext }
    catch e
      err = e
    cb err, ret

  #---------

  _parse : (raw) ->
    [err, packets] = parse raw
    cb err, packets

  #---------

  _decrypt : (cb) ->
    err = null
    esc = make_esc cb, "Message::decrypt"
    await @_get_session_key esc defer is_enc, sesskey
    if is_enc
      await @_find_encrypted_data esc defer edat
      await @_decrypt_with_session_key sesskey, edat, esc defer plaintext
      await @_parse plaintext, esc defer packets
      @packets = packets.concat @packets
    cb err 

  #---------

  _inflate : (cb) ->
    packets = []
    esc = make_esc cb, "Message::_inflate"
    for p in @packets
      await @p.inflate esc defer inflated
      if inflated? then packets.push inflated...
      else packets.push  p
    @packets = packets
    cb null

  #---------
  
  process : (cb) ->
    esc = make_esc cb, "Message:process"
    await @_decrypt esc defer()
    await @_inflate esc defer()
    await @_verify esc defer()
    cb null, @literals

#==========================================================================================


exports.KeyBlock = KeyBlock

#==========================================================================================
