
{make_esc} = require 'iced-error'
{OPS} = require '../keyfetch'
konst = require '../const'
C = konst.openpgp
{katch,unix_time,athrow,Warnings,bufeq_secure} = require '../util'
{parse} = require './parser'
{import_key_pgp} = require '../symmetric'
util = require 'util'
armor = require './armor'
hashmod = require '../hash'
verify_clearsign = require('./clearsign').verify
verify_detached = require('./detachsign').verify

#==========================================================================================

class KeyBlock

  constructor : (@packets, opts) ->
    # We'll throw away signatures that aren't verified.
    @verified_signatures = []
    @subkeys = []
    @primary = null
    @userids = []
    @user_attributes = []
    @warnings = new Warnings()
    @opts = opts or {}
    @opts.strict = true if not @opts.strict?

  #--------------------

  to_obj : () -> return { @subkeys, @primary, @userids }

  #--------------------

  _extract_keys : () ->
    err = null
    #for p in @packets when p.is_primary?()
    #  console.log util.inspect(p, { depth : null })
    #  console.log p.get_fingerprint().toString('hex')
    if not @packets.length
      err = new Error "No packets; cannot extract a key"
    else if not (@primary = @packets[0]).is_primary()
      err = new Error "First packet must be the primary key"
    else
      for p,i in @packets[1...] when (p.is_key_material() and not err?)
        if p.key.is_toxic() then @warnings.push "Ignoring toxic subkey (ElGamal Encrypt+Sign)"
        else if not p.is_primary() then @subkeys.push p
        # Google End-to-End seems to write the public key twice
        else if bufeq_secure(p.get_fingerprint(), @primary.get_fingerprint())
          p.set_duplicate_primary()
        else err = new Error "cannot have 2 primary keys"
    err

  #--------------------

  _check_keys : () -> @_check_primary() or @_check_subkeys()

  #--------------------

  _check_primary : () ->
    err = if not @primary.is_self_signed()
      new Error "no valid primary key self-signature or key(s) have expired"
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
      if k.is_signed_subkey_of @primary, @opts
        @subkeys.push k
      else
        msg = "Subkey #{i} was invalid; discarding"
        @warnings.push msg
    err

  #--------------------

  process : (cb) ->
    err = @_extract_keys()
    await @_verify_sigs defer err unless err?
    err = @_check_keys() unless err? or @opts?.no_check_keys
    cb err

  #--------------------

  _verify_sigs : (cb) ->
    err = null
    working_set = []
    n_sigs = 0
    # No sense in processing packet 1, since it's the primary key!
    for p,i in @packets[1...] when not err?
      if not p.is_signature()
        if n_sigs > 0
          n_sigs = 0
          working_set = []
        working_set.push p unless p.is_duplicate_primary()
      else if not bufeq_secure((iid = p.get_issuer_key_id()), (pid = @primary.get_key_id()))
        n_sigs++
        @warnings.push "Skipping signature by another issuer: #{iid?.toString('hex')} != #{pid?.toString('hex')}"
      else
        n_sigs++
        p.key = @primary.key
        p.primary = @primary
        await p.verify working_set, defer(tmp), @opts
        if tmp?
          msg = "Signature failure in packet #{i}: #{tmp.message} (#{pid.toString('hex')})"
          @warnings.push msg
          # discard the signature, see the above comment...
        else
          @verified_signatures.push p
    cb err

  #--------------------

#==========================================================================================

class Message

  #---------

  constructor : ({@keyfetch, @data_fn, @data, @strict, @now}) ->
    @literals = []
    @enc_data_packet = null
    @warnings = new Warnings()

  #---------

  _get_session_key : (cb) ->
    key_ids = []
    esk_packets = []
    err = null
    pkcs5 = false

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
      await @keyfetch.fetch key_ids, konst.ops.decrypt, defer err, km, index
      unless err?
        packet = esk_packets[index]
        key_material = km.find_pgp_key_material(key_ids[index])
        fingerprint = key_material.get_fingerprint()
        privk = key_material.key
        await privk.decrypt_and_unpad packet.ekey, {fingerprint}, defer err, sesskey, pkcs5
        unless err?
          @encryption_subkey = key_material
    else
      enc = false

    cb err, enc, sesskey, pkcs5

  #---------

  _find_encrypted_data : (cb) ->
    err = ret = null
    if @packets.length and (ret = @packets[0].to_enc_data_packet())
      @packets.pop()
    else err = new Error "Could not find encrypted data packet"
    cb err, ret

  #---------

  _decrypt_with_session_key : (sesskey, edat, pkcs5, cb) ->
    [err,cipher] = katch () -> import_key_pgp sesskey, pkcs5
    unless err?
      await edat.decrypt {cipher}, defer err, ret
    cb err, ret

  #---------

  _parse : (raw, cb) ->
    [err, packets] = parse raw
    cb err, packets

  #---------

  _decrypt : (cb) ->
    err = null
    esc = make_esc cb, "Message::decrypt"
    await @_get_session_key esc defer is_enc, sesskey, pkcs5
    if is_enc
      await @_find_encrypted_data esc defer edat
      await @_decrypt_with_session_key sesskey, edat, pkcs5, esc defer plaintext
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
      err = new Error "signature mismatch open v close: #{a?.toString('hex')} != #{b?.toString('hex')}"

    unless err?
      await @keyfetch.fetch [ a ], konst.ops.verify, defer err, km, i
      if err?
        err = new Error "Can't find a key for #{a.toString('hex')}: #{err.message}"

    if not err?

      key_material = km.find_pgp_key_material(a)
      sig.close.key = key_material.key
      sig.close.subkey_material = key_material

      # This is used by the front-end in keybase, though nowhere else in kbpgpg
      sig.close.key_manager = km

      # If this succeeds, then we'll go through and mark each
      # packet in sig.payload with the successful sig.close.
      await sig.close.verify sig.payload, defer(err), { @now }

    else if not @strict
      @warnings.push "Problem fetching key #{a.toString('hex')}: #{err.toString()}"
      err = null

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

  _process_generic : ({packets}, cb) ->
    @packets = packets
    esc = make_esc cb, "Message:process"
    await @_decrypt esc defer()
    await @_inflate esc defer()
    await @_verify esc defer()
    cb null, @collect_literals()

  #---------

  _verify_clearsign : ({packets, clearsign}, cb) ->
    if not clearsign?
      err = new Error "no clearsign data found"
    else
      await verify_clearsign { packets, clearsign, @keyfetch }, defer err, literal
    cb err, [ literal ]

  #---------

  parse_and_inflate : (body, cb) ->
    esc = make_esc cb, "Message::parse_and_inflate"
    await @_parse body, esc defer @packets
    await @_inflate esc defer()
    cb null, @collect_literals()

  #---------

  parse_and_process : (msg, cb) ->
    esc = make_esc cb, "Message::parse_and_process"
    await @_parse msg.body, esc defer packets
    await @_process {msg, packets}, esc defer literals
    cb null, literals

  #---------

  _verify_signature : ({packets}, cb) ->
    if not(@data? or @data_fn?)
      err = new Error "Cannot verify detached signature without data input"
    else
      await verify_detached { packets, @data, @data_fn, @keyfetch}, defer err, literals
    cb err, literals

  #---------

  _process : ({msg, packets}, cb) ->
    msg.type or= C.message_types.generic
    switch msg.type
      when C.message_types.generic
        await @_process_generic { packets }, defer err, literals
      when C.message_types.clearsign
        await @_verify_clearsign { packets, clearsign : msg.clearsign } , defer err, literals
      when C.message_types.signature
        await @_verify_signature { packets } , defer err, literals
      else
        err = new Error "Needed a 'generic', 'clearsign', or 'signature' PGP message, got #{msg.type}"
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
# @param {Buffer} raw The raw buffer, without PGP armoring. If you provide this,
#    you should also provide a `msg_type` argument.
# @param {Number} msg_type The type of the `raw` message provided above. Should be
#    one of C.message_types.{generic,clearsign,signature}.
# @param {KeyFetcher} keyfetch A KeyFetch object that is called to get keys
#    for decyrption and signature verification.
# @param {Function} data_fn A function to call with data. Used in the case
#    of detached signatures.  data_fn is called repeatedly with a hasher object.
#    It calls back with (err,done).
# @param {Buffer} data Instead of a streaming data_fn, you can also specify
#    a static buffer, to check against the given signature.
# @param {Boolean} strict In strict mode, all signatures must verify, and we're in
#    strict mode by default.  In non-strict mode, sigs that we can't find keys for
#    just generate warnings.
# @param {callback} cb Callback with an `err, Array<Literals>, Warnings` triples. On success,
#    we will get a series of PGP literal packets, some of which might be signed.
exports.do_message = do_message = ({armored, raw, msg_type, keyfetch, data_fn, data, strict}, cb) ->
  literals = null
  err = msg = warnings = esk = null
  if armored?
    [err,msg] = armor.decode armored
  else if raw?
    msg_type or= C.message_types.generic
    msg = { body : raw, type : msg_type }
  else
    err = new Error "No input to do_message; need either 'armored' or 'raw' input"
  unless err?
    if not strict? then strict = true
    proc = new Message { keyfetch, data_fn, data, strict }
    await proc.parse_and_process msg, defer err, literals
    warnings = proc.warnings
    esk = proc.encryption_subkey
  cb err, literals, warnings, esk

#==========================================================================================
