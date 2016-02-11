{RSA} = require '../rsa'
{ECDSA} = require '../ecc/ecdsa'
{SHA256} = require '../hash'
K = require('../const').kb
C = require('../const').openpgp
{make_esc} = require 'iced-error'
{format_pgp_fingerprint_2,athrow,assert_no_nulls,ASP,katch,bufeq_secure,unix_time,bufferify} = require '../util'
{ops_to_keyflags} = require './util'
{Lifespan,Subkey,Primary} = require '../keywrapper'

{Message,encode,decode} = require './armor'
{parse} = require './parser'
{KeyBlock} = require './processor'

opkts = require './packet/all'
{read_base64,unseal} = require '../keybase/encode'
{P3SKB} = require '../keybase/packet/p3skb'
{KeyFetcher,KeyFetched} = require '../keyfetch'
{SignatureEngine} = require './sigeng'
{Encryptor} = require 'triplesec'
{KeyManagerInterface} = require '../kmi'

##
## KeyManager
##
##   Manage the generation, import and export of keys, in either OpenPGP or
##   keybase form.  For now, we're only using PGP form, for convenience
##   of the different clients (since otherwise they'd need to reimplement
##   RSA, etc.)
##
#=================================================================

class Engine
  constructor : ({@primary, @subkeys, @userids, @key_manager}) ->
    @packets = []
    @messages = []
    @_allocate_key_packets()
    (k.primary = @primary for k in @subkeys)
    @_index_keys()
    true

  #---------

  _index_keys : () ->
    @_index = {}
    for k in @_all_keys()
      @_index[@ekid(k)] = k

  #---------

  ekid : (k) -> @key(k).ekid()

  #---------

  _allocate_key_packets : () ->
    @_v_allocate_key_packet @primary, { subkey : false }
    for key in @subkeys
      @_v_allocate_key_packet key, { subkey : true }

  #--------

  _all_keys : () -> [ @primary ].concat @subkeys
  self_sign_primary : (args, cb) -> @_v_self_sign_primary args, cb

  #--------

  get_all_key_materials : () ->
    [[@key(@primary), true]].concat ([ @key(k), false ] for k in @subkeys)

  #--------

  sign_subkeys : ({time, asp}, cb) ->
    err = null
    for subkey in @subkeys when not err?
      await @_v_sign_subkey {asp, time, subkey}, defer err
    cb err

  #--------

  get_subkey_materials : () -> (@key(k) for k in @subkeys)

  #--------

  is_locked : () ->
    for k,i in @_all_keys()
      return true if @key(k).is_locked()
    return false

  #--------

  has_private : () ->
    for k in @_all_keys()
      return true if @key(k).has_private()
    return false

  #--------

  sign : ({asp, time}, cb) ->
    await @self_sign_primary { asp, time }, defer err
    await @sign_subkeys { asp, time }, defer err unless err?
    cb err

  #--------

  check_eq : (eng2) ->
    err = null
    if not @primary.key.eq(eng2.primary.key)
      err = new Error "Primary keys don't match"
    else if @subkeys.length isnt eng2.subkeys.length
      err = new Error "different # of subkeys"
    else
      for key, i in @subkeys when not @err?
        if not key.key.eq(eng2.subkeys[i].key)
          err = new Error "subkey #{i} doesn't match"
    err

  #--------

  merge_private : (eng2) ->
    err = @_merge_private_primary eng2
    unless err?
      for k,i  in eng2.subkeys
        break if (err = @_merge_private_subkey k, i)?
    return err

  #--------

  _merge_private_primary : (eng2) ->
    err = if not @key(eng2.primary).has_secret_key_material() then null
    else if @_merge_1_private(@primary, eng2.primary) then null
    else new Error "primary public key doesn't match private key"
    return err

  #--------

  _merge_private_subkey : (k2, i) ->
    err = if not @key(k2).has_secret_key_material() then null
    else if not ((ekid = @ekid(k2)))? then new Error "Subkey #{i} is malformed"
    else if not ((k = @_index[ekid]))? then new Error "Subkey #{i} wasn't found in public key"
    else if @_merge_1_private(k, k2) then null
    else new Error "subkey #{i} can't be merged"
    return err

  #--------

  unlock_keys : ({asp, passphrase, tsenc}, cb) ->
    esc = make_esc cb, "Engine::unlock_keys"
    await @key(@primary).unlock {asp, tsenc, passphrase }, esc defer()
    for subkey, i in @subkeys when @key(subkey).has_private()
      await @key(subkey).unlock {asp, tsenc, passphrase }, esc defer()
    cb null

  #--------

  export_keys_to_keyring : (km) ->
    x = (key_wrapper, is_primary) => {
      km,
      is_primary,
      key_wrapper,
      key_material : @key(key_wrapper),
      key : @key(key_wrapper).key
    }
    [ x(@primary, true) ].concat( x(k,false) for k in @subkeys )

  #--------

  _merge_1_private : (k1, k2) ->
    if bufeq_secure(@ekid(k1), @ekid(k2))
      @key(k1).merge_private @key(k2)
      true
    else
      false

  #--------

  merge_subkey_omitting_revokes : (k) ->
    ekid = k.ekid()
    if (kw = @_index[ekid])?
      kw.overwrite_with_omitting_revokes k
    else
      @_index[ekid] = k
      @subkeys.push k

  #--------

  merge_public_omitting_revokes : (pgpeng2) ->
    @primary.overwrite_with_omitting_revokes pgpeng2.primary
    @merge_all_subkeys_omitting_revokes pgpeng2

  #--------

  merge_all_subkeys_omitting_revokes : (pgpeng2) ->
    for subkey in pgpeng2.subkeys
      @merge_subkey_omitting_revokes subkey

  #--------

  check_not_expired : ({subkey_material, now} )  ->
    now or= unix_time()
    err = @key(@primary).check_not_expired { now }
    err = subkey_material.check_not_expired { now } unless err?
    return err

#=================================================================

lifespan_from_keywrapper_and_time = ({key_wrapper, time}) ->
  ret = key_wrapper.lifespan
  if time?
    ret = ret.copy()
    ret.generated = time
  ret

#=================================================================

class PgpEngine extends Engine

  #--------

  constructor : ({primary, subkeys, userids, @user_attributes, key_manager}) ->
    super { primary, subkeys, userids, key_manager }

  #--------

  key : (k) -> k._pgp

  #--------

  _v_allocate_key_packet : (key, opts) ->
    unless key._pgp?
      key._pgp = new opkts.KeyMaterial {
        key : key.key,
        timestamp : key.lifespan.generated,
        flags : key.flags,
        opts }

  #--------

  _v_self_sign_primary : ({time, asp, raw_payload}, cb) ->
    lifespan = lifespan_from_keywrapper_and_time { key_wrapper : @primary, time }
    await @key(@primary).self_sign_key { lifespan, @userids, raw_payload }, defer err, sigs
    cb err, sigs

  #--------

  _v_sign_subkey : ({asp, subkey, time}, cb) ->
    lifespan = lifespan_from_keywrapper_and_time { key_wrapper : subkey, time }
    await @key(@primary).sign_subkey { subkey : @key(subkey), lifespan }, defer err
    cb err

  #--------

  clear_psc: () ->
    @key(@primary).clear_psc()
    for u in @userids
      u.clear_psc()
    for s in @subkeys
      @key(s).clear_psc()

  #--------

  set_passphrase : (pp) ->
    @primary.passphrase = pp
    for k in @subkeys
      k.passphrase = pp

  #--------

  _export_keys_to_binary : (opts) ->
    packets = [ @key(@primary).export_framed(opts) ]
    for userid in @userids
      packets.push userid.write(), userid.get_framed_signature_output()
    opts.subkey = true
    for subkey in @subkeys
      packets.push @key(subkey).export_framed(opts), @key(subkey).get_subkey_binding_signature_output()
    assert_no_nulls packets
    Buffer.concat packets

  #--------

  export_keys : (opts) ->
    mt = C.message_types
    type = if opts.private then mt.private_key else mt.public_key
    msg = @_export_keys_to_binary opts
    encode type, msg

  #--------

  export_to_p3skb : () ->
    pub = @_export_keys_to_binary { private : false }
    priv_clear = @_export_keys_to_binary { private : true }
    new P3SKB { pub, priv_clear }

  #--------

  find_key : (key_id) ->
    for k in @_all_keys()
      if bufeq_secure @key(k).get_key_id(), key_id
        return k
    return null

  #--------

  find_key_material : (key_id) ->
    key = @find_key key_id
    if key? then @key(key) else null

  #--------

  get_key_id : () -> @key(@primary).get_key_id()
  get_short_key_id : () -> @key(@primary).get_short_key_id()
  get_fingerprint : () -> @key(@primary).get_fingerprint()
  get_ekid : () -> @key(@primary).ekid()

  #--------

  get_all_key_ids : () -> (@key(k).get_key_id() for k in @_all_keys())

  #--------

  validity_check : (cb) ->
    err = null
    for k in @_all_keys()
      await @key(k).validity_check defer err
      break if err?
    cb err

  #--------

  # @returns {openpgp.KeyMaterial} An openpgp KeyMaterial wrapper.
  find_best_key : (flags, need_priv = false) ->
    best = null

    check = (k) =>
      km = @key(k) # KeyMaterial
      ok1 = km.fulfills_flags(flags) or ((k.flags & flags) is flags)
      ok2 = not(need_priv) or km.has_private()
      ok3 = not km.is_revoked()
      return (ok1 && ok2 && ok3)

    for k in @subkeys when check(k)
      if not best? then best = k
      else if @key(k).is_preferable_to(@key(best)) then best = k

    if not best? and check(@primary) then best = @primary
    return (if best? then @key(best) else null)

  #--------
  #
  # So this class fits the KeyFetcher template.
  #
  # @param {Array<String>} key_ids A list of PGP Key Ids, as an array of strings
  # @param {Number} op_mask A bitmask of Ops that we need to perform with this key,
  #    taken from kbpgp.const.ops
  # @param {callback} cb Callback with `err, key, i, @`
  fetch : (key_ids, op_mask, cb) ->
    flags = ops_to_keyflags op_mask

    err = key = ret = null
    key = null
    ret_i = null

    for kid,i in key_ids when not key?
      key = @find_key kid
      ret_i = i if key?

    if not key?
      err = new Error "No keys match the given key IDs"
    else if not @key(key).fulfills_flags flags
      err = new Error "We don't have a key for the requested PGP ops (flags = #{flags})"
    else
      ret = @key(key)

    cb err, @key_manager, ret_i

#=================================================================

class KeyManager extends KeyManagerInterface

  constructor : ({@primary, @subkeys, @userids, @armored_pgp_public, @armored_pgp_private, @user_attributes, signed}) ->
    @pgp = new PgpEngine { @primary, @subkeys, @userids, @user_attributes, key_manager : @ }
    @engines = [ @pgp ]
    @_signed = if signed? then signed else false
    @p3skb = null

  #========================
  # Public Interface

  #
  # @generate
  #
  # Generate a new key bundle from scratch.  Make the given number of subkeys, and also the primary.
  # All generated keys are RSA
  #
  # @param {ASP} asp A standard Async Package.
  # @param {string|Buffer} userid The userID to bake into the key
  # @param {string|Buffer} userids The userIDs to bake into the key (specify >= 1); the first
  #   one specified gets the Primary flag.
  # @param {object} primary Specify the `flags`, `nbits`, and `expire_in` for the primary
  #   key.  If not specified, defaults are ALLFLAGS, 4096, and 0, respectively.
  # @param {Array<object>} subkeys As for primary, specify the `flags`, `nbits`, and `expire_in`
  #   and `algo` for all subkeys.  Defaults are (sign|encrypt|auth), 2048, 8 years, and
  #   RSA respectively.
  # @param {Boolean} ecc Whether to use ECC or RSA.  Off by default.
  # @param {callback} cb Callback with <Error, KeyManager> pair.
  #
  # Deprecated options:
  #
  # @param {Array<number>} sub_flags An array of flags to use for the subkeys, one for
  #    each subkey.  For instance, if you want one subkey for signing and one for encryption,
  #    then you should pass the different flags here. [DEPRECATED]
  # @param {number} nsubs The number of subkeys to create, all with the standard panel
  #    of keyflags.  If you want to specify the keyflags for each subkey, then you should
  #    use the sub_flags above, which take precedence. [DEPRECATED]
  # @param {number} primary_flags The flags to use for the primary, which defaults
  #    to nearly all of them [DEPRECATED]
  # @param {number} nbits The number of bits to use for all keys.  If left unspecified, then assume
  #   defaults of 4096 for the master, and 2048 for the subkeys [DEPRECATED]
  # @param {object} expire_in When the keys should expire.  By default, it's 0 and 8 years. [DEPRECATED]
  #
  @generate : ({asp, userid, userids, primary, subkeys, ecc,
                 sub_flags, nsubs, primary_flags, nbits, expire_in, generated}, cb) ->
    asp = ASP.make asp
    F = C.key_flags
    KEY_FLAGS_STD = F.sign_data | F.encrypt_comm | F.encrypt_storage | F.auth
    KEY_FLAGS_PRIMARY = KEY_FLAGS_STD | F.certify_keys

    primary or= {}
    primary.flags or= primary_flags or KEY_FLAGS_PRIMARY
    primary.expire_in or= expire_in?.primary or K.key_defaults.primary.expire_in
    primary.algo or= (if ecc then ECDSA else RSA)
    primary.nbits or= nbits or K.key_defaults.primary.nbits[primary.algo.klass_name]

    sub_flags = (KEY_FLAGS_STD for i in [0...nsubs]) if nsubs? and not sub_flags?
    subkeys or= ( { flags } for flags in sub_flags)
    for subkey in subkeys
      subkey.expire_in or= expire_in?.subkey or K.key_defaults.sub.expire_in
      subkey.flags or= KEY_FLAGS_STD
      subkey.algo or= primary.algo.subkey_algo subkey.flags
      subkey.nbits or= nbits or K.key_defaults.sub.nbits[subkey.algo.klass_name]

    generated or= unix_time()
    esc = make_esc cb, "KeyManager::generate"

    if userid?
      userids = [ userid ]
    if userids? and Array.isArray(userids)
      userids = ( new opkts.UserID(u) for u in userids )
    else
      err = new Error "Need either 'userid' or 'userids' specified as an array"
      await athrow err, esc defer()

    gen = ( {klass, section, params, primary}, cb) ->
      asp.section section
      await params.algo.generate { asp, nbits: params.nbits }, defer err, key
      unless err?
        my_generated = params.generated or generated
        lifespan = new Lifespan { generated : my_generated, expire_in : params.expire_in }
        wrapper = new klass { key, lifespan, flags : params.flags, primary }
      cb err, wrapper

    await gen { klass : Primary, section : "primary", params : primary }, esc defer primary
    subkeys_out = []
    for subkey,i in subkeys
      await gen { klass : Subkey, section : "subkey #{i+1}", params : subkey, primary }, esc defer s
      subkeys_out.push s

    bundle = new KeyManager { primary, subkeys : subkeys_out, userids }
    cb null, bundle

  #------------

  @generate_rsa : ({asp, userid, userids}, cb) ->
    F = C.key_flags
    primary = {
      flags : F.certify_keys
      nbits : 4096
    }
    subkeys = [{
      flags : F.encrypt_storage | F.encrypt_comm,
      nbits : 2048
    },{
      flags : F.sign_data | F.auth
      nbits : 2048
    }]

    KeyManager.generate { asp, userid, userids, primary, subkeys }, cb

  #------------

  @generate_ecc : ({asp, userid, userids, generated}, cb) ->
    F = C.key_flags
    primary = {
      flags : F.certify_keys
      nbits : 384
      algo : ECDSA
    }
    subkeys = [{
      flags : F.encrypt_storage | F.encrypt_comm,
      nbits : 256
    },{
      flags : F.sign_data | F.auth
      nbits : 256
    }]

    KeyManager.generate { asp, userid, userids, primary, subkeys, generated }, cb

  #------------

  # The triplesec encoder will be primed (hopefully) with the output
  # of running Scrypt on the new passphrase, and the user's actual
  # salt.  We'll need this to encrypt server-stored key, or to derive
  # the key to encrypt a PGP secret key with s2k/AES-128-CFB.
  set_enc : (e) -> @tsenc = e

  #------------

  # Start from an armored PGP PUBLIC KEY BLOCK, and parse it into packets.
  # Also works for an armored PGP PRIVATE KEY BLOCK
  #
  # @param {Buffer|String} armored The armored PGP string
  # @param {Buffer} binary The decoded raw binary PGP message
  # @param {Buffer|String} raw Synonym for 'armored' above (DEPRECATED).
  # @param {ASP} asp
  # @param {callback<err,KeyManager,Warnings>} cb Callback with the result;
  #    On success, we'll get an actual KeyManager.
  #
  @import_from_armored_pgp : ({armored, raw, binary, asp, opts}, cb) ->
    msg = binary
    err = null

    unless msg?
      raw or= armored
      asp = ASP.make asp
      warnings = null
      ret = null
      [err,msg] = decode raw
      unless err?
        if not (msg.type in [C.message_types.public_key, C.message_types.private_key])
          err = new Error "Wanted a public or private key; got: #{msg.type}"

    unless err?
      await KeyManager.import_from_pgp_message { msg, asp, opts }, defer err, ret, warnings, packets

    # For keys that have unprotected secret key data, just unlock
    # the secret key material by default, that way we don't have to
    # call unlock_pgp() on an unlocked key (which is confusing).
    if not(err?)
      await ret.simple_unlock {}, defer err

    cb err, ret, warnings, packets

  #--------------

  simple_unlock : (opts, cb) ->
    err = null
    # For keys that have unprotected secret key data, just unlock
    # the secret key material by default, that way we don't have to
    # call unlock_pgp() on an unlocked key (which is confusing).
    if @has_pgp_private() and not @is_pgp_locked()
      await @unlock_pgp {}, defer err
    cb err

  #--------------

  # @param {string} armored A string that has the base64-encoded P3SKB format
  # @param {string} raw A synonym for 'armored' (DEPRECATED)
  @import_from_p3skb : ({raw, armored, asp}, cb) ->
    armored or= raw
    asp = ASP.make asp
    km = null
    warnings = null
    [err, p3skb] = katch () -> P3SKB.alloc unseal read_base64 armored
    unless err?
      msg = new Message { body : p3skb.pub, type : C.message_types.public_key }
      await KeyManager.import_from_pgp_message {msg, asp}, defer err, km, warnings
      km.p3skb = p3skb if km?
    cb err, km, warnings

  #--------------

  unlock_p3skb : ({asp, tsenc, passphrase, passphrase_generation}, cb) ->
    asp = ASP.make asp
    if not tsenc? and passphrase?
      tsenc = new Encryptor { key : bufferify(passphrase) }
    await @p3skb.unlock { tsenc, asp, passphrase_generation }, defer err
    unless err?
      msg = new Message { body : @p3skb.priv.data, type : C.message_types.private_key }
      await KeyManager.import_from_pgp_message { msg, asp }, defer err, km

    unless err?
      err = @pgp.merge_private km.pgp

    # The private key isn't locked, but it is stored in 's2k' notation
    # and needs to be decoded.  That happens with this call (w/ a NULL pw)
    unless err?
      passphrase = new Buffer []
      await @unlock_pgp { passphrase }, defer err

    cb err

  #--------------

  # Import from a dearmored/decoded PGP message.
  @import_from_pgp_message : ({msg, asp, opts}, cb) ->
    asp = ASP.make asp
    bundle = null
    warnings = null
    unless err?
      [err,packets] = parse msg.body
    unless err?
      kb = new KeyBlock packets, opts
      await kb.process defer err
      warnings = kb.warnings
    unless err?
      bundle = new KeyManager {
        primary : KeyManager._wrap_pgp(Primary, kb.primary),
        subkeys : (KeyManager._wrap_pgp(Subkey, k) for k in kb.subkeys),
        armored_pgp_public : msg.raw(),
        user_attributes : kb.user_attributes,
        userids : kb.userids,
        signed : true }
    unless err?
      await bundle.check_pgp_validity defer err
    cb err, bundle, warnings, packets

  #------------

  # After importing the public portion of the key previously,
  # add the private portions with this call.  And again, verify
  # signatures.  And check that the public portions agree.
  merge_pgp_private : ({armored, raw, asp}, cb) ->
    asp = ASP.make asp
    esc = make_esc cb, "merge_pgp_private"
    await KeyManager.import_from_armored_pgp { armored, raw, asp }, esc defer b2
    err = @pgp.merge_private b2.pgp

    if err? then # noop
    else if not @has_pgp_private()
      err = new Error "no private key material found after merge"
    else
      await @simple_unlock {}, esc defer()
    cb err

  #------------

  # Given a second keymanager, check that the PGP keys all match.
  check_pgp_public_eq : (km2) -> @pgp.check_eq km2.pgp

  #------------

  # Open the private PGP key with the given passphrase
  # (which is going to be different from our strong keybase passphrase).
  unlock_pgp : ({passphrase}, cb) ->
    await @pgp.unlock_keys { passphrase }, defer err
    cb err

  #-----

  is_pgp_locked : () -> @pgp.is_locked()
  is_keybase_locked : () -> @keybase.is_locked()
  has_pgp_private : () -> @pgp.has_private()
  has_p3skb_private : () -> @p3skb?.has_private()
  has_keybase_private : () -> @keybase.has_private()
  is_p3skb_locked : () -> @p3skb?.is_locked()

  #-----

  # Open the private MPIs of the secret key, and check for sanity.
  # Use the given triplesec.Encryptor / password object.
  unlock_keybase : ({tsenc, asp}, cb) ->
    asp = ASP.make asp
    await @keybase.unlock_keys { tsenc, asp }, defer err
    cb err

  #-----

  # A private export consists of:
  #   1. The PGP public key block
  #   2. The PGP private key block (Public and private keys, triplesec'ed)
  export_private_to_server : ({tsenc, asp, passphrase_generation}, cb) ->
    asp = ASP.make asp
    err = ret = null
    unless (err = @_assert_signed())?
      p3skb = @pgp.export_to_p3skb()
      await p3skb.lock { tsenc, asp, passphrase_generation }, defer err
    unless err?
      ret = p3skb.frame_packet_armored { dohash : true }
    cb err, ret

  #-----

  # Export to a PGP PRIVATE KEY BLOCK, stored in PGP format
  # We'll need to reencrypt with a derived key
  export_pgp_private_to_client : ({passphrase, regen}, cb) ->
    err = null
    passphrase = bufferify passphrase if passphrase?
    if regen or not (msg = @armored_pgp_private)?
      unless (err = @_assert_signed())?
        @armored_pgp_private = msg = @pgp.export_keys({private : true, passphrase})
    cb err, msg

  export_pgp_private : (args...) -> @export_pgp_private_to_client args...

  #-----

  # Export the PGP PUBLIC KEY BLOCK stored in PGP format to the client.
  # @param {Callback} cb A callback to return an error and the armored payload.
  export_pgp_public : ({regen}, cb) ->
    err = null
    if regen or not (msg = @armored_pgp_public)?
      unless (err = @_assert_signed())?
        @armored_pgp_public = msg = @pgp.export_keys({private : false})
    cb err, msg

  #-----

  # @param {Callback} cb A callback to return an error and the armored payload.
  export_public : ({asp, regen} = {}, cb = null) ->
    await @export_pgp_public { asp, regen }, defer err, msg
    cb err, msg

  #-----

  export_private : ({passphrase, p3skb, asp, passphrase_generation }, cb) ->
    if p3skb
      tsenc = new Encryptor { key : bufferify(passphrase) }
      await @export_private_to_server { tsenc, asp, passphrase_generation }, defer err, res
    else
      await @export_pgp_private_to_client { passphrase , asp }, defer err, res
    cb err, res

  #-----

  pgp_full_hash : (opts, cb) ->
    esc = make_esc cb, "get_pgp_full_hash"
    await @export_pgp_public opts, esc defer armored
    cb null, (new SHA256 new Buffer armored.trim()).toString("hex")

  #-----

  sign_pgp : ({asp, time}, cb) -> @pgp.sign { asp, time }, cb

  #-----

  sign : ({asp, time }, cb) ->
    asp = ASP.make asp
    asp.section "sign"
    asp.progress { what : "sign PGP" , total : 1, i : 0 }
    await @sign_pgp     { asp, time }, defer err
    asp.progress { what : "sign PGP" , total : 1, i : 1 }
    @_signed = true unless err?
    cb err

  #--------

  get_userids : () -> @userids

  #--------

  # Take the vouched-for user IDs, and for each one, look up all of the signatures on
  # the user ID.  For each signature, pull out what time it was signed, and whether it's marked
  # primary.  Then go through this list and (1) deduplicate; and (2) figure out which userid
  # was marked primary most recently, and mark that one primary.  This will change the underlying
  # UserID objects, altering their most_recent_sig and primary fields.
  get_userids_mark_primary : () ->
    max = null
    max_s = null
    tab = {}

    mymax = (a, b) ->
      if not a? and not b? then null
      else if not a? then b
      else if not b? then a
      else if a > b  then a
      else b

    for userid,i in @userids when userid?
      s = userid.utf8()
      pair = userid.time_primary_pair()
      obj = { userid, pair, i }
      do_insert = false

      if (prev = tab[s])?
        primary_time = mymax(prev.pair[1], pair[1])
        if not(prev.pair[0]?) or (pair[0] and prev.pair[0] < pair[0])
          do_insert = true
      else
        primary_time = pair[1]
        do_insert = true

      tab[s] = obj if do_insert

      if primary_time? and ((not max?) or max < primary_time)
        max_s = s
        max = primary_time
    if max_s? then tab[max_s].userid.primary = true
    ret = []

    for k,obj of tab
      obj.userid.most_recent_sig = obj.pair[0]
      ret.push obj.userid

    return ret

  #--------

  # So this class fits the KeyFetcher template.
  #
  # @param {Array<String>} key_ids A list of PGP Key Ids, as an array of strings
  # @param {Array<Number>} flags an Array of flags that can be flattened into one
  # @param {callback} cb Callback with `err, key`
  #
  fetch : (key_ids, flags, cb) -> @pgp.fetch key_ids, flags, cb

  find_pgp_key : (key_id) -> @pgp.find_key key_id
  find_pgp_key_material : (key_id) -> @pgp.find_key_material key_id
  find_best_pgp_key : (flags, need_priv) -> @pgp.find_best_key flags, need_priv
  find_signing_pgp_key : () -> @find_best_pgp_key C.key_flags.sign_data, true
  find_verifying_pgp_key : () -> @find_best_pgp_key C.key_flags.sign_data, false
  find_crypt_pgp_key : (need_priv = false) -> @find_best_pgp_key C.key_flags.encrypt_comm, need_priv
  can_verify : () -> @find_verifying_pgp_key()?
  can_sign : () -> @find_signing_pgp_key()?
  can_encrypt : () -> @find_crypt_pgp_key(false)?
  can_decrypt : () -> @find_crypt_pgp_key(true)?

  #--------

  # Returns the underlying crypto key that's the primary key.
  # @return {RSA::Pair} an RSA keypair (or DSA eventually)
  get_primary_keypair : -> @primary.key

  #--------

  # Get all of the subkey material for each of the PGP subkeys
  get_all_pgp_key_materials : -> @pgp.get_all_key_materials()

  #--------

  export_pgp_keys_to_keyring : () -> @pgp.export_keys_to_keyring @

  get_pgp_key_id : () -> @pgp.get_key_id()
  get_pgp_short_key_id : () -> @pgp.get_short_key_id()
  get_pgp_fingerprint : () -> @pgp.get_fingerprint()
  get_pgp_fingerprint_str : () -> @get_pgp_fingerprint()?.toString 'hex'
  get_ekid : () -> @pgp.get_ekid()

  #----------------

  clear_pgp_internal_sigs : () -> @pgp.clear_psc()

  #----------------

  get_all_pgp_key_ids : () -> @pgp.get_all_key_ids()

  #----------------

  get_ekid_b64_str : () ->
    if (k = @get_ekid())? then base64u.encode k
    else null

  #----------------

  # An FP2 is a Fingeprint in the case of PGP and a WebBase64(kid)
  get_fp2 : () -> @get_pgp_fingerprint()
  get_fp2_formatted : (opts) -> if (p = @get_fp2())? then format_pgp_fingerprint_2(p, opts) else null

  #----------------

  get_type : () -> "pgp"

  #----------------

  # Check the validity of all PGP keypairs
  check_pgp_validity : (cb) -> @pgp.validity_check cb

  #----------------

  make_sig_eng : () -> new SignatureEngine { km : @ }

  # /Public Interface
  #========================

  _apply_to_engines : ({args, meth}, cb) ->
    err = null
    for e in @engines when not err
      await meth.call e, args, defer(err)
    cb err

  #----------

  _assert_signed : () ->
    if @_signed then null else new Error "need to sign before export"

  #----------

  # @param {openpgp.KeyMaterial} kmp An openpgp KeyMaterial packet
  @_wrap_pgp : (klass, kmp) ->
    new klass {
      key : kmp.key,
      lifespan : new Lifespan { generated : kmp.timestamp, expire_in : kmp.get_expire_time()?.expire_in }
      _pgp : kmp
    }

  #----------

  merge_all_subkeys_omitting_revokes : (km2) ->
    if @pgp? and km2.pgp? then @pgp.merge_all_subkeys_omitting_revokes km2.pgp

  #----------

  pgp_check_not_expired : ( { subkey_material, now} ) ->
    @pgp.check_not_expired { subkey_material, now }

  merge_public_omitting_revokes : (km2) ->
    if @pgp? and km2.pgp? then @pgp.merge_public_omitting_revokes km2.pgp

  #----------

  merge_userids : (km2) ->
    # One way that users can prove ownership of their PGP key (besides actually
    # making a sigchain link with it) is to sign their Keybase email into it as
    # a userid. Thus when we merge keys, it's important that we also merge
    # id's, or else we could incorrectly report an updated key as unowned just
    # because a past version of it was unproven.
    #
    # This is a fairly naive merge, which doesn't try to do anything fancy like
    # ensuring the latest-expiring id packets. It just looks for id's in km2
    # that are completely missing, and appends the ones that it finds. Note
    # that it's important to modify the @userids list in place, rather than
    # assigning to it, because it gets copied around.
    if not @pgp? or not km2.pgp?
      return
    existing_utf8_strings = {}
    for existing_userid in @userids
      existing_utf8_strings[existing_userid.utf8()] = true
    for candidate_userid in km2.get_userids_mark_primary()
      if candidate_userid.utf8() not of existing_utf8_strings
        @userids.push(candidate_userid)

  #----------

  merge_everything : (km2) ->
    @merge_public_omitting_revokes(km2)
    @merge_userids(km2)

#=================================================================

exports.KeyManager = KeyManager
exports.opkts = opkts

#=================================================================
