
{make_esc} = require 'iced-error'
{OPS} = require '../keyfetch'
konst = require '../const'
C = konst.openpgp
{bufeq_secure} = require '../util'
{parse} = require './parser'
{import_key_pgp} = require '../symmetric'
util = require 'util'

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

  constructor : (@key_fetch) ->
    @literals = []
    @enc_data_packet = null

  #---------

  _get_session_key : (cb) ->
    key_ids = []
    esk_packets = []
    err = null

    # Handle the case that the Session Key is encrypted N times, and we
    # only have the key decrypt one of them.  This is the case when you send
    # one email to many people, all encrypted with their corresponding public
    # keys.  It might not come up, but we may as well handle it.
    key_ids = while @packets.length and (p = @packets[0].to_esk_packet())
      esk_packets.push p
      @packets.shift()
      p.get_key_id()

    if key_ids.length 
      enc = true      
      await @key_fetch.fetch key_ids, [ konst.ops.decrypt ], defer err, obj, index
      unless err?
        packet = esk_packets[index]
        await obj.key.decrypt_and_unpad packet.ekey, defer err, sesskey
    else
      enc = false

    cb err, enc, sesskey

  #---------

  _find_encrypted_data : (cb) ->
    err = ret = null
    if @packets.length and (ret = @packets[0].to_enc_data_packet())
      @packets.pop()
    else err = new Error "Could not find encrypted data packet"
    cb err, ret

  #---------

  _decrypt_with_session_key : (sesskey, edat, cb) ->
    err = null
    try
      cipher = import_key_pgp sesskey
      ret = edat.decrypt cipher
    catch e
      err = e
    cb err, ret

  #---------

  _parse : (raw, cb) ->
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
      await p.inflate esc defer inflated
      if inflated? 
        await @_parse inflated, esc defer p
        packets.push p...
      else packets.push p
    @packets = packets
    cb null

  #---------

  # This does our best to handle nested signatures.  It won't crash, but it will
  # give weird results on garbage in, which will likely cause signature verification
  # to fail.
  _frame_signatures : () ->
    ret = []
    stack = []
    payload = []
    for p in @packets
      if p.tag is C.packet_tags.one_pass_sig 
        stack.push { open : p }
      else if not stack.length then # noop
      else if p.tag is C.packet_tags.signature
        o = stack.pop()
        o.close = p
        ret.push o
      else 
        payload.push p

    for o in ret
      o.payload = payload
    ret

  #---------

  _verify_sig : (sig, cb) ->
    err = null
    if not bufeq_secure (a = sig.open.key_id), (b = sig.close.get_key_id())
      err = new Error "signature mismatch: #{a.toString('hex')}} != #{b.toString('hex')}"

    unless err?
      await @key_fetch.fetch [ a ], [ konst.ops.verify ], defer err, obj

    unless err?
      sig.close.key = obj.key
      await sig.close.verify sig.payload, defer err

    unless err?
      for p in sig.payload
        p.add_signed_by sig.close

    cb err

  #---------

  _verify : (cb) ->
    esc = make_esc cb, "Message::_verify_sigs"
    sigs = @_frame_signatures()
    for sig in sigs
      await @_verify_sig sig, esc defer()
    cb null

  #---------

  collect_literals : () ->
    (p for p in @packets when p.tag is C.packet_tags.literal)

  #---------
  
  process : (packets, cb) ->
    @packets = packets
    esc = make_esc cb, "Message:process"
    await @_decrypt esc defer()
    await @_inflate esc defer()
    await @_verify esc defer()
    cb null, @collect_literals()

  #---------

  parse_and_process : (raw, cb) ->
    await @_parse raw, defer err, packets
    await @process packets, defer err, literals unless err?
    cb err, literals

  #---------

#==========================================================================================

exports.KeyBlock = KeyBlock
exports.Message = Message

#==========================================================================================
