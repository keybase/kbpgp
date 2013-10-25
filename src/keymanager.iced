{RSA} = require './rsa'
K = require('./const').kb
C = require('./const').openpgp
{make_esc} = require 'iced-error'
{bufeq_secure,unix_time,bufferify} = require './util'
{UserIds,Lifespan,Subkey,Primary} = require './keywrapper'
{read_base64,box,unbox} = require './keybase/encode'

{encode,decode} = require './openpgp/armor'
{parse} = require './openpgp/parser'
{KeyBlock} = require './openpgp/processor'

opkts = require './openpgp/packet/all'
kpkts = require './keybase/packet/all'

##
## KeyManager
## 
##   Manage the generation, import and export of keys, in either OpenPGP or
##   keybase form.
##

#=================================================================

class Encryption 
  constructor : ({@tsenc, passphrase}) ->
    @passphrase = bufferify passphrase
    @tsenc or= new triplesec.Encryptor { version : 2, @passphrase }

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

  sign_subkeys : ({asp}, cb) -> 
    err = null
    for subkey in @subkeys when not err?
      await @_v_sign_subkey {asp, subkey}, defer err
    cb err

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
        userid : @userids.get_openpgp() }

  #--------
  
  userid_packet : () ->
    @_uidp = new opkts.UserID @userids.get_openpgp() unless @_uidp?
    @_uidp

  #--------
  
  _v_self_sign_primary : ({asp}, cb) ->
    await @primary._pgp.self_sign_key { lifespan : @primary.lifespan, uidp : @userid_packet() }, defer err, @self_sig
    cb err

  #--------
  
  _v_sign_subkey : ({asp, subkey}, cb) ->
    await @primary._pgp.sign_subkey { subkey : subkey._pgp, lifespan : subkey.lifespan }, defer err, sig
    subkey._pgp_sig = sig
    cb err

  #--------

  set_passphrase : (pp) ->
    @primary.passphrase = pp
    for k in @subkeys
      k.passphrase = pp

  #--------

  export_keys : (opts) ->
    packets = [ @primary._pgp.export_framed(opts), @userid_packet().write(), @self_sig ]
    opts.subkey = true
    for subkey in @subkeys
      packets.push subkey._pgp.export_framed(opts), subkey._pgp_sig
    buf = Buffer.concat(packets)
    mt = C.message_types
    type = if opts.private then mt.private_key else mt.public_key
    encode type, Buffer.concat(packets)

  #--------

  find_key : (key_id) ->
    for k in @_all_keys()
      if bufeq_secure k._pgp.get_key_id(), key_id
        return k 
    return null

#=================================================================

class KeybaseEngine extends Engine

  constructor : ({primary, subkeys, userids}) ->
    super { primary, subkeys, userids }

  #--------

  key : (k) -> k._keybase

  #-----

  _check_can_sign : (keys,cb) ->
    err = null
    for k in keys when not err?
      err = new Error "cannot sign; don't have private key" unless k.key.can_sign()
    cb err

  #-----

  _v_allocate_key_packet : (key) ->
    unless key._keybase?
      key._keybase = new kpkts.KeyMaterial { 
        key : key.key, 
        timestamp : key.lifespan.generated }

  #-----

  _v_self_sign_primary : ({asp}, cb) ->
    esc = make_esc cb, "KeybaseEngine::_v_self_sign_primary"
    await @_check_can_sign [@primary], esc defer()
    p = new kpkts.SelfSign { key_wrapper : @primary, userid : @userids.get_keybase() }
    await p.sign { asp, include_body : true }, esc defer @self_sig
    cb null

  #-----

  _v_sign_subkey : ({asp, subkey}, cb) ->
    esc = make_esc cb, "KeybaseEngine::_v_sign_subkey"
    subkey._keybase_sigs = {}
    await @_check_can_sign [ @primary, subkey ], esc defer()
    p = new kpkts.Subkey { subkey }
    await p.sign { asp, include_body : true }, esc defer subkey._keybase_sigs.fwd
    p = new kpkts.SubkeyReverse { subkey }
    await p.sign { asp , include_body : true }, esc defer subkey._keybase_sigs.rev
    cb null

  #-----

  export_keys : (opts, cb) ->
    opts.tag = if opts.private then K.packet_tags.private_key_bundle else K.packet_tags.public_key_bundle
    ret = new kpkts.KeyBundle.alloc opts
    esc = make_esc cb, "KeybaseEngine::export_keys"
    await @primary._keybase.export_key opts, esc defer primary
    ret.set_primary {
      key : primary
      sig : @self_sig
    }
    for k in @subkeys
      await k._keybase.export_key opts, esc defer key
      ret.push_subkey {
        key : key
        sigs :
          forward : k._keybase_sigs.fwd
          reverse : k._keybase_sigs.rev
      }
    cb null, ret.frame_packet()

#=================================================================

class KeyManager

  constructor : ({@primary, @subkeys, @userids, @armored_pgp_public, @armored_pgp_private}) ->
    @pgp = new PgpEngine { @primary, @subkeys, @userids }
    @keybase = new KeybaseEngine { @primary, @subkeys, @userids }
    @engines = [ @pgp, @keybase ]
    @_signed = false

  #========================
  # Public Interface

  # Generate a new key bunlde from scratch.  Make the given number
  # of subkeys.
  @generate : ({asp, nsubs, userid, nbits }, cb) ->
    userids = new UserIds { keybase : userid, openpgp : userid }
    generated = unix_time()
    esc = make_esc cb, "KeyManager::generate"
    asp.section "primary"
    await RSA.generate { asp, nbits: (nbits or K.key_defaults.primary.nbits) }, esc defer key
    lifespan = new Lifespan { generated, expire_in : K.key_defaults.primary.expire_in }
    primary = new Primary { key, lifespan }
    subkeys = []
    lifespan = new Lifespan { generated, expire_in : K.key_defaults.sub.expire_in }
    for i in [0...nsubs]
      asp.section "subkey #{i+1}"
      await RSA.generate { asp, nbits: (nbits or K.key_defaults.sub.nbits) }, esc defer key
      subkeys.push new Subkey { key, desc : "subkey #{i}", primary, lifespan }
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
  @import_from_armored_pgp : ({raw, asp, userid}, cb) ->
    ret = null
    [err,msg] = decode raw
    unless err?
      if not (msg.type in [C.message_types.public_key, C.message_types.private_key])
        err = new Error "Wanted a public or private key; got: #{msg.type}"
    unless err?
      await KeyManager.import_from_pgp_message { msg, asp, userid }, defer err, ret
    cb err, ret

  #--------------

  # Import from a dearmored/decoded PGP message.
  @import_from_pgp_message : ({msg, raw, asp, userid}, cb) ->
    bundle = null
    unless err?
      [err,packets] = parse msg.body
    unless err?
      kb = new KeyBlock packets
      await kb.process defer err
    unless err?
      userids = new UserIds { openpgp : kb.userid, keybase : userid }
      bundle = new KeyManager { 
        primary : KeyManager._wrap_pgp(Primary, kb.primary), 
        subkeys : (KeyManager._wrap_pgp(Subkey, k) for k in kb.subkeys), 
        armored_pgp_public : msg.raw(),
        userids }
    cb err, bundle

  #------------

  # Import from a base64-encoded-purepacked keybase key structure
  @import_from_packed_keybase : ({raw, asp}, cb) ->
    [err, tag_and_body ] = unbox read_base64 raw
    [err, bundle] = kpkts.KeyBundle.alloc_nothrow tag_and_body unless err?
    await bundle.verify { asp }, defer err unless err?
    ret = if err? then null else new KeyManager bundle.export_to_obj()
    cb err, ret
 
  #------------

  # After importing the public portion of the key previously,
  # add the private portions with this call.  And again, verify
  # signatures.  And check that the public portions agree.
  merge_pgp_private : ({raw, asp}, cb) ->
    await KeyManager.import_from_armored_pgp { raw, asp }, defer err, b2
    err = @pgp.merge_private b2.pgp unless err?
    cb err

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
  has_keybase_private : () -> @keybase.has_private()

  #-----
  
  # Open the private MPIs of the secret key, and check for sanity.
  # Use the given triplesec.Encryptor / password object.
  unlock_keybase : ({tsenc, asp}, cb) ->
    await @keybase.unlock_keys { tsenc, asp }, defer err
    cb err

  #-----
  
  # A private export consists of:
  #   1. The PGP public key block
  #   2. The keybase message (Public and private keys, triplesec'ed)
  export_private_to_server : ({tsenc, asp}, cb) ->
    err = ret = null
    if not (err = @_assert_signed())?
      pgp = @pgp.export_keys { private : false }
      await @keybase.export_keys { private : true, tsenc, asp }, defer err, keybase
    ret = if err? then null else { pgp, keybase : box(keybase).toString('base64') }
    cb err, ret

  #-----
  
  # Export to a PGP PRIVATE KEY BLOCK, stored in PGP format
  # We'll need to reencrypt with a derived key
  export_pgp_private_to_client : ({passphrase, asp, regen}, cb) ->
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
    msg = @armored_pgp_public unless regen
    msg = @pgp.export_keys({private : false}) unless msg?
    cb null, msg

  #-----

  sign_pgp : ({asp}, cb) -> @pgp.sign { asp }, cb
  sign_keybase : ({asp}, cb) -> @keybase.sign { asp }, cb

  #-----

  sign : ({asp}, cb) ->
    asp?.section "sign"
    asp?.progress { what : "sign PGP" , total : 1, i : 0 }
    await @sign_pgp     { asp }, defer err
    asp?.progress { what : "sign PGP" , total : 1, i : 1 }
    asp?.progress { what : "sign keybase" , total : 1, i : 0 }
    await @sign_keybase { asp }, defer err unless err?
    asp?.progress { what : "sign keybase" , total : 1, i : 1 }
    @_signed = true unless err?
    cb err

  #--------

  find_pgp_key : (key_id) -> @pgp.find_key key_id

  export_pgp_keys_to_keyring : () -> @pgp.export_keys_to_keyring @
  export_keybase_keys_to_keyring : () -> @keybase.export_keys_to_keyring @
  
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
exports.Encryption = Encryption
exports.UserIds = UserIds

#=================================================================

