
{make_esc} = require 'iced-error'
{OPS} = require '../keyfetch'
konst = require '../const'
C = konst.openpgp
{unix_time,athrow,Warnings,bufeq_secure} = require '../util'
{parse} = require './parser'
{import_key_pgp} = require '../symmetric'
util = require 'util'
armor = require './armor'
hashmod = require '../hash'
verify_clearsign = require('./clearsign').verify

#==========================================================================================

class KeyBlock

  constructor : (@packets) ->
    # We'll throw away signatures that aren't verified.
    @verified_signatures = []
    @subkeys = []
    @primary = null
    @userids = []
    @user_attributes = []
    @warnings = new Warnings()

  #--------------------

  to_obj : () -> return { @subkeys, @primary, @userids }

  #--------------------

  _extract_keys : () ->
    err = null
    if not @packets.length
      err = new Error "No packets; cannot extract a key"
    else if not (@primary = @packets[0]).is_primary() 
      err = new Error "First packet must be the primary key"
    else
      for p,i in @packets[1...] when (p.is_key_material() and not err?)
        if p.key.is_toxic() then @warnings.push "Ignoring toxic subkey (ElGamal Encrypt+Sign)"
        else if not p.is_primary() then @subkeys.push p
        else err = new Error "cannot have 2 primary keys"
    err

  #--------------------

  _check_keys : () -> @_check_primary() or @_check_subkeys()

  #--------------------

  _check_primary : () ->
    err = if not @primary.is_self_signed()
      new Error "no valid primary key self-signature"
    else if (@userids = @primary.get_signed_userids()).length is 0
      new Error "no valid Userid signed into key"
    else 
      @user_attributes = @primary.get_signed_user_attributes()
      null

  #--------------------

  _check_subkeys : () ->
    subkeys = @subkeys 
    err = null
    @subkeys = []
    for k,i in subkeys when not err?
      if k.is_signed_subkey_of @primary
        @subkeys.push k
      else 
        msg = "Subkey #{i} was invalid; discarding"
        @warnings.push msg
    err

  #--------------------

  process : (cb) ->
    err = @_extract_keys()
    await @_verify_sigs defer err unless err?
    err = @_check_keys() unless err?
    cb err

  #--------------------

  _verify_sigs : (cb) ->
    # No sense in processing packet 1, since it's the primary key!
    err = null
    working_set = []
    n_sigs = 0
    for p,i in @packets[1...] when not err?
      if not p.is_signature() 
        if n_sigs > 0
          n_sigs = 0
          working_set = []
        working_set.push p
      else if not bufeq_secure((iid = p.get_issuer_key_id()), (pid = @primary.get_key_id()))
        n_sigs++
        @warnings.push "Skipping signature by another issuer: #{iid?.toString('hex')} != #{pid?.toString('hex')}"
      else
        n_sigs++
        p.key = @primary.key
        p.primary = @primary
        await p.verify working_set, defer tmp
        if tmp?
          msg = "Signature failure in packet #{i}: #{tmp.message}"
          @warnings.push msg
          # discard the signature, see the above comment...
        else
          @verified_signatures.push p
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
      await @key_fetch.fetch key_ids, konst.ops.decrypt, defer err, obj, index
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
      await @key_fetch.fetch [ a ], konst.ops.verify, defer err, obj

    unless err?
      sig.close.key = obj.key

      # This is used by the front-end in keybase, though nowhere else in kbpgpg
      sig.close.keyfetch_obj = obj

      # If this succeeds, then we'll go through and mark each
      # packet in sig.payload with the successful sig.close.
      await sig.close.verify sig.payload, defer err

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

  verify_clearsign : (packets, clearsign, cb) ->
    await verify_clearsign { packets, clearsign, @key_fetch }, defer err, literal
    cb err, [ literal ]

  #---------

  parse_and_process : ({body, clearsign}, cb) ->
    await @_parse body, defer err, packets
    unless err?
      if clearsign?
        await @verify_clearsign packets, clearsign, defer err, literals
      else
        await @process packets, defer err, literals
    cb err, literals

#==========================================================================================

exports.KeyBlock = KeyBlock
exports.Message = Message

#==========================================================================================

# A convenience wrapper function for handling incoming armored PGP messages.
# We will decode, parse and process them, hoping to open any decryption and
# verify any signatures.
#
# @param {string} armored The armored PGP generic message.
# @param {KeyFetcher} keyfetch A KeyFetch object that is called to get keys
#    for decyrption and signature verification.
# @param {callback} cb Callback with an `err, Array<Literals>` pairs. On success,
#    we will get a series of PGP literal packets, some of which might be signed.
#    
#
exports.do_message = do_message = ({armored, keyfetch}, cb) ->
  [err,msg] = armor.decode armored
  literals = null
  unless err?
    proc = new Message keyfetch
    switch msg.type
      when C.message_types.generic, C.message_types.clearsign
        await proc.parse_and_process msg, defer err, literals
      else
        err = new Error "Needed a 'generic' PGP message, but got something else"
  cb err, literals

#==========================================================================================
