{RSA} = require './rsa'
K = require('./const').kb
C = require('./const').openpgp
{make_esc} = require 'iced-error'
{assert_no_nulls,ASP,katch,bufeq_secure,unix_time,bufferify} = require './util'
{UserId,Lifespan,Subkey,Primary} = require './keywrapper'

{Message,encode,decode} = require './openpgp/armor'
{parse} = require './openpgp/parser'
{KeyBlock} = require './openpgp/processor'

opkts = require './openpgp/packet/all'
{read_base64,box,unbox,box} = require './keybase/encode'
{P3SKB} = require './keybase/packet/p3skb'

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
  constructor : ({@primary, @subkeys, @userids}) ->
    @packets = []
    @messages = []
    @_allocate_key_packets()
    (k.primary = @primary for k in @subkeys)
    true

  #---------

  ekid : (k) -> @key(k).ekid()

  #---------
  
  _allocate_key_packets : () ->
    for key in @_all_keys()
      @_v_allocate_key_packet key

  #--------

  _all_keys : () -> [ @primary ].concat @subkeys
  self_sign_primary : (args, cb) -> @_v_self_sign_primary args, cb

  #--------

  get_all_key_materials : () ->
    [[@key(@primary), true]].concat ([ @key(k), false ] for k in @subkeys)

  #--------

  sign_subkeys : ({asp}, cb) -> 
    err = null
    for subkey in @subkeys when not err?
      await @_v_sign_subkey {asp, subkey}, defer err
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
      return false unless @key(k).has_private()
    return true

  #--------

  sign : ({asp}, cb) ->
    await @self_sign_primary { asp }, defer err
    await @sign_subkeys { asp }, defer err unless err?
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
    err = null
    if not @key(eng2.primary).has_private()
      err = new Error "Expected a private key; got a public key!"
    else if not @_merge_1_private @primary, eng2.primary
      err = new Error "primary public key doesn't match private key"
    else if @subkeys.length isnt eng2.subkeys.length
      err = new Error "Different number of subkeys"
    else
      for key, i in @subkeys when not err?
        if not @key(eng2.subkeys[i]).has_private()
          err = new Error "Subkey #{i} doesn't have a private key"
        else if not @_merge_1_private key, eng2.subkeys[i]
          err = new Error "Subkey #{i} doesn't match its public key"
    err

  #--------

  unlock_keys : ({asp, passphrase, tsenc}, cb) ->
    esc = make_esc cb, "Engine::unlock_keys"
    await @key(@primary).unlock {asp, tsenc, passphrase }, esc defer()
    for subkey in @subkeys
      await @key(subkey).unlock {asp, tsenc, passphrase }, esc defer()
    cb null

  #--------

  export_keys_to_keyring : (km) ->
    x = (key_wrapper, is_primary) =>
      { km, is_primary, key_wrapper, key_material : @key(key_wrapper), key : @key(key_wrapper).key }
    [ x(@primary, true) ].concat( x(k,false) for k in @subkeys )

  #--------

  _merge_1_private : (k1, k2) ->
    if bufeq_secure(@ekid(k1), @ekid(k2))
      @key(k1).merge_private @key(k2)
      true
    else
      false

#=================================================================

class PgpEngine extends Engine

  #--------
  
  constructor : ({primary, subkeys, userids}) ->
    super { primary, subkeys, userids }

  #--------

  key : (k) -> k._pgp
  
  #--------
  
  _v_allocate_key_packet : (key) ->
    unless key._pgp?
      key._pgp = new opkts.KeyMaterial { 
        key : key.key, 
        timestamp : key.lifespan.generated, 
        flags : key.flags }

  #--------
  
  _v_self_sign_primary : ({asp}, cb) ->
    await @key(@primary).self_sign_key { lifespan : @primary.lifespan, @userids }, defer err
    cb err

  #--------
  
  _v_sign_subkey : ({asp, subkey}, cb) ->
    await @key(@primary).sign_subkey { subkey : @key(subkey), lifespan : subkey.lifespan }, defer err
    cb err

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

  get_key_id : () -> @key(@primary).get_key_id()
  get_fingerprint : () -> @key(@primary).get_fingerprint()

  #--------

  # @returns {openpgp.KeyMaterial} An openpgp KeyMaterial wrapper.
  find_best_key : (flags) ->
    wrapper = null
    check = (k) => @key(k).fulfills_flags(flags) or ((k.flags & flags) is flags)
    for k in @subkeys when not wrapper?
      if check(k) then wrapper = k
    if not wrapper? and check(@primary) then wrapper = @primary
    return (if wrapper? then @key(wrapper) else null)
    
  #--------

  #
  # So this class fits the KeyFetcher template.
  #
  # @param {Array<String>} key_ids A list of PGP Key Ids, as an array of strings
  # @param {Array<Number>} flags an Array of flags that can be flattened into one
  # @param {callback} cb Callback with `err, key`
  fetch : (key_ids, flags, cb) -> 

    err = key = null
    key = null
    ff = 0
    (ff |= flag for flag in flags)

    for kid in key_ids when not key?
      key = @find_key kid

    err = if not key then new Error "No keys match the given fingerprint"
    else if not @key(key).fulfills_flags ff then new Error "We don't have a key for the requested PGP ops"

    cb err, key

#=================================================================

class KeyManager

  constructor : ({@primary, @subkeys, @userids, @armored_pgp_public, @armored_pgp_private}) ->
    @pgp = new PgpEngine { @primary, @subkeys, @userids }
    @engines = [ @pgp ]
    @_signed = false
    @p3skb = null

  #========================
  # Public Interface

  # Generate a new key bunlde from scratch.  Make the given number
  # of subkeys.
  #
  # @param {ASP} asp A standard Async Package.
  # @param {Array<number>} sub_flags An array of flags to use for the subkeys, one for
  #    each subkey.  For instance, if you want one subkey for signing and one for encryption,
  #    then you should pass the different flags here.
  # @param {number} nsubs The number of subkeys to create, all with the standard panel
  #    of keyflags.  If you want to specify the keyflags for each subkey, then you should
  #    use the sub_flags above, which take precedence.
  # @param {number} primary_flags The flags to use for the primary, which defaults to nearly all of them
  # @param {string} userid The userID to bake into the key
  # @param {number} nbits The number of bits to use for all keys.  If left unspecified, then assume
  #   defaults of 4096 for the master, and 2048 for the subkeys
  @generate : ({asp, sub_flags, nsubs, primay_flags, userid, nbits }, cb) ->
    asp = ASP.make asp

    F = C.key_flags
    KEY_FLAGS_STD = F.sign_data | F.encrypt_comm | F.encrypt_storage | F.auth
    KEY_FLAGS_PRIMARY = KEY_FLAGS_STD | F.certify_keys

    primary_flags = KEY_FLAGS_PRIMARY unless primary_flags?
    sub_flags = (KEY_FLAGS_STD for i in [0...nsubs]) if not sub_flags? and nsubs?

    userids = [ new opkts.UserID userid ]
    generated = unix_time()
    esc = make_esc cb, "KeyManager::generate"
    asp.section "primary"
    await RSA.generate { asp, nbits: (nbits or K.key_defaults.primary.nbits) }, esc defer key

    lifespan = new Lifespan { generated, expire_in : K.key_defaults.primary.expire_in }
    primary = new Primary { key, lifespan, flags : primary_flags }

    subkeys = []
    lifespan = new Lifespan { generated, expire_in : K.key_defaults.sub.expire_in }
    for flags in sub_flags
      asp.section "subkey #{i+1}"
      await RSA.generate { asp, nbits: (nbits or K.key_defaults.sub.nbits) }, esc defer key
      subkeys.push new Subkey { key, desc : "subkey #{i}", primary, lifespan, flags }

    bundle = new KeyManager { primary, subkeys, userids }

    cb null, bundle

  #------------

  # The triplesec encoder will be primed (hopefully) with the output
  # of running Scrypt on the new passphrase, and the user's actual
  # salt.  We'll need this to encrypt server-stored key, or to derive
  # the key to encrypt a PGP secret key with s2k/AES-128-CFB.
  set_enc : (e) -> @tsenc = e

  #------------
 
  # Start from an armored PGP PUBLIC KEY BLOCK, and parse it into packets.
  # Also works for an armored PGP PRIVATE KEY BLOCK
  @import_from_armored_pgp : ({raw, asp}, cb) ->
    asp = ASP.make asp
    ret = null
    [err,msg] = decode raw
    unless err?
      if not (msg.type in [C.message_types.public_key, C.message_types.private_key])
        err = new Error "Wanted a public or private key; got: #{msg.type}"
    unless err?
      await KeyManager.import_from_pgp_message { msg, asp }, defer err, ret
    cb err, ret

  #--------------

  @import_from_p3skb : ({raw, asp}, cb) ->
    asp = ASP.make asp
    km = null
    [err, p3skb] = katch () -> P3SKB.alloc unbox read_base64 raw
    unless err?
      msg = new Message { body : p3skb.pub, type : C.message_types.public_key }
      await KeyManager.import_from_pgp_message {msg, asp}, defer err, km
      km.p3skb = p3skb if km?
    cb err, km

  #--------------

  unlock_p3skb : ({asp, tsenc}, cb) ->
    asp = ASP.make asp
    await @p3skb.unlock { tsenc, asp }, defer err
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
  @import_from_pgp_message : ({msg, asp}, cb) ->
    asp = ASP.make asp
    bundle = null
    unless err?
      [err,packets] = parse msg.body
    unless err?
      kb = new KeyBlock packets
      await kb.process defer err
    unless err?
      bundle = new KeyManager { 
        primary : KeyManager._wrap_pgp(Primary, kb.primary), 
        subkeys : (KeyManager._wrap_pgp(Subkey, k) for k in kb.subkeys), 
        armored_pgp_public : msg.raw(),
        userids : kb.userids }
    cb err, bundle

  #------------

  # After importing the public portion of the key previously,
  # add the private portions with this call.  And again, verify
  # signatures.  And check that the public portions agree.
  merge_pgp_private : ({raw, asp}, cb) ->
    asp = ASP.make asp
    await KeyManager.import_from_armored_pgp { raw, asp }, defer err, b2
    err = @pgp.merge_private b2.pgp unless err?
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
  export_private_to_server : ({tsenc, asp}, cb) ->
    asp = ASP.make asp
    err = ret = null
    unless (err = @_assert_signed())?
      p3skb = @pgp.export_to_p3skb()
      await p3skb.lock { tsenc, asp }, defer err
    unless err?
      ret = box(p3skb.frame_packet()).toString('base64')
    cb err, ret

  #-----
  
  # Export to a PGP PRIVATE KEY BLOCK, stored in PGP format
  # We'll need to reencrypt with a derived key
  export_pgp_private_to_client : ({passphrase, asp, regen}, cb) ->
    asp = ASP.make asp
    err = msg = null
    passphrase = bufferify passphrase if passphrase?
    if not regen? and (msg = @armored_pgp_private) then #noop
    else if not (err = @_assert_signed())?
      msg = @pgp.export_keys({private : true, passphrase})
    cb err, msg

  #-----
  
  # Export the PGP PUBLIC KEY BLOCK stored in PGP format
  # to the client...
  export_pgp_public : ({asp, regen}, cb) ->
    asp = ASP.make asp
    err = null
    unless (err = @_assert_signed())?
      msg = @armored_pgp_public unless regen
      msg = @pgp.export_keys({private : false}) unless msg?
    cb err, msg

  #-----

  sign_pgp : ({asp}, cb) -> @pgp.sign { asp }, cb

  #-----

  sign : ({asp}, cb) ->
    asp = ASP.make asp
    asp.section "sign"
    asp.progress { what : "sign PGP" , total : 1, i : 0 }
    await @sign_pgp     { asp }, defer err
    asp.progress { what : "sign PGP" , total : 1, i : 1 }
    @_signed = true unless err?
    cb err

  #--------

  #
  # So this class fits the KeyFetcher template.
  #
  # @param {Array<String>} key_ids A list of PGP Key Ids, as an array of strings
  # @param {Array<Number>} flags an Array of flags that can be flattened into one
  # @param {callback} cb Callback with `err, key`
  fetch : (key_ids, flags, cb) -> @pgp.fetch key_ids, flags, cb


  find_pgp_key : (key_id) -> @pgp.find_key key_id
  find_best_pgp_key : (flags) -> @pgp.find_best_key flags

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
  get_pgp_fingerprint : () -> @pgp.get_fingerprint()
  
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
      lifespan : new Lifespan { generated : kmp.timestamp }
      _pgp : kmp
    }

  #----------
#=================================================================

exports.KeyManager = KeyManager
exports.UserId = UserId

#=================================================================

