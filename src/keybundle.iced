{RSA} = require './rsa'
K = require('./const').kb
C = require('./const').openpgp
{make_esc} = require 'iced-error'
{unix_time,bufferify} = require './util'
{Lifespan,Subkey,Primary} = require './keywrapper'
{encode,decode} = require './openpgp/armor'

opkts = require './openpgp/packet/all.iced'
kpkts = require './keybase/packet/all.iced'

#=================================================================

class Encryption 
  constructor : ({@tsenc, passphrase}) ->
    @passphrase = bufferify passphrase
    @tsenc or= new triplesec.Encryptor { version : 2, @passphrase }

#=================================================================

class UserIds
  constructor : ({@openpgp, @keybase}) ->
  get_keybase : () -> "#{@keybase}@keybase.io"
  get_openpgp : () -> @openpgp or @get_keybase()

#=================================================================

class Engine
  constructor : ({@primary, @subkeys, @userids}) ->
    @packets = []
    @messages = []
    @_allocate_key_packets()

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

#=================================================================

class PgpEngine extends Engine

  #--------
  
  constructor : ({primary, subkeys, userids}) ->
    super { primary, subkeys, userids }

  #--------
  
  _v_allocate_key_packet : (key) ->
    key._pgp = new opkts.KeyMaterial { key : key.key, timestamp : key.lifespan.generated, userid : @userids.get_keybase() }

  #--------
  
  userid_packet : () ->
    @_uidp = new opkts.UserID @userids.get_keybase() unless @_uidp?
    @_uidp

  #--------
  
  _v_self_sign_primary : ({asp}, cb) ->
    await @primary._pgp.self_sign_key { lifespan : @primary.lifespan, uidp : @userid_packet() }, defer err, @self_sig
    cb err

  #--------
  
  _v_sign_subkey : ({asp, subkey}, cb) ->
    arg = 
      primary : @primary._pgp, 
      lifespan : subkey.lifespan
    await subkey._pgp.sign_primary arg, defer err, primary_binding
    unless err?
      arg.subkey = subkey._pgp
      arg.primary_binding = primary_binding
      await @primary._pgp.sign_subkey arg, defer err, sig
    subkey._pgp_sig = sig    
    cb err

  #--------

  export_public_to_client : () ->
    packets = [ @primary._pgp.public_framed(), @userid_packet().write(), @self_sig ]
    for subkey in @subkeys
      packets.push subkey._pgp.public_framed({subkey : true}), subkey._pgp_sig
    encode C.message_types.public_key, Buffer.concat(packets)

#=================================================================

class KeybaseEngine extends Engine

  constructor : ({primary, subkeys, userids}) ->
    super { primary, subkeys, userids }

  #-----

  _v_allocate_key_packet : (key) ->
    key._keybase = new kpkts.KeyMaterial { key : key.key, timestamp : key.generated, userid : @userids.get_keybase() }

  #-----

  _v_self_sign_primary : ({asp}, cb) ->
    esc = make_esc cb, "KeybaseEngine::_v_self_sign_primary"
    @self_sigs = {}
    p = new kpkts.SelfSignKeybaseUsername { key_wrapper : @primary, @userids }
    await p.sign { asp }, esc defer @self_sigs.openpgp
    p = new kpkts.SelfSignPgpUserid { key_wrapper : @primary, @userids }
    await p.sign { asp }, esc defer @self_sigs.keybase
    cb null

  #-----

  _v_sign_subkey : ({asp, subkey}, cb) ->
    p = new kpkts.SubkeySignature { @primary, subkey }
    await p.sign { asp }, defer err, sig
    subkey._keybase_sig = sig
    cb err

#=================================================================

class KeyBundle

  constructor : ({@primary, @subkeys, @userids}) ->
    @tsenc = null
    @pgp = new PgpEngine { @primary, @subkeys, @userids }
    @keybase = new KeybaseEngine { @primary, @subkeys, @userids }
    @engines = [ @pgp, @keybase ]

  #========================
  # Public Interface

  # Generate a new key bunlde from scratch.  Make the given number
  # of subkeys.
  @generate : ({asp, nsubs, userid }, cb) ->
    userids = new UserIds { keybase : userid }
    generated = unix_time()
    esc = make_esc cb, "KeyBundle::generate"
    asp.section "primary"
    await RSA.generate { asp, nbits: K.key_defaults.primary.nbits }, esc defer key
    lifespan = new Lifespan { generated, expire_in : K.key_defaults.primary.expire_in }
    primary = new Primary { key, lifespan }
    subkeys = []
    lifespan = new Lifespan { generated, expire_in : K.key_defaults.sub.expire_in }
    for i in [0...nsubs]
      asp.section "subkey #{i+1}"
      await RSA.generate { asp, nbits: K.key_defaults.sub.nbits }, esc defer key
      subkeys.push new Subkey { key, desc : "subkey #{i}", primary, lifespan }
    bundle = new KeyBundle { primary, subkeys, userids }

    cb null, bundle

  #------------

  # The triplesec encoder will be primed (hopefully) with the output
  # of running Scrypt on the new passphrase, and the user's actual
  # salt.  We'll need this to encrypt server-stored key, or to derive
  # the key to encrypt a PGP secret key with s2k/AES-128-CFB.
  set_enc : (e) -> @tsenc = e

  #------------
 
  # Start from an armored PGP PUBLIC KEY BLOCK, and parse it into packets.
  @import_from_armored_pgp_public : ({raw, asp}, cb) ->

  #------------
 
  # Verify a key for sanity, and check its signatures, and that the keys
  # haven't expired.
  verify : ({asp}, cb) ->

  #------------
 
  # After importing the public portion of the key previously,
  # add the private portions with this call.  And again, verify
  # signatures.  And check that the public portions agree.
  add_armored_pgp_private : ({raw, asp}, cb) ->

  #------------
 
  # Open the private PGP key with the given passphrase
  # (which is going to be different from our strong keybase passphrase).
  open_pgp : ({passphrase}, cb) ->

  #-----
  
  # Open the private MPIs of the secret key, and check for sanity.
  # Use the given triplesec.Encryptor / password object.
  open_keybase : ({asp}, cb) ->

  #-----
  
  # The export consists of
  #   1. A PGP message (potentially redacted from upload)
  #   2. A keybase message (Public key only)
  export_public_to_server : ({asp}, cb) ->

  #-----
  
  # A private export consists of:
  #   1. The redacted PGP message
  #   2. The keybase message (Public and private keys)
  export_private_to_server : ({asp}, cb) ->

  #-----
  
  # Export to a PGP PRIVATE KEY BLOCK, stored in PGP format
  # We'll need to reencrypt with a derived key
  export_pgp_private_to_client : ({asp}, cb) ->

  #-----
  
  # Export the PGP PUBLIC KEY BLOCK stored in PGP format
  # to the client...
  export_pgp_public_to_client : ({asp}, cb) ->
    msg = @pgp.export_public_to_client()
    cb null, msg

  #-----

  sign : ({asp}, cb) ->
    esc = make_esc cb, "KeyBundle::_sign_pgp"
    await @_self_sign_primary { asp }, esc defer()
    await @_sign_subkeys { asp }, esc defer()
    cb null

  # /Public Interface
  #========================
  
  _self_sign_primary : (args, cb) ->
    @_apply_to_engines { args, meth : Engine.prototype.self_sign_primary }, cb

  #----------

  _sign_subkeys : (args, cb) ->
    @_apply_to_engines { args, meth : Engine.prototype.sign_subkeys }, cb

  #----------

  _apply_to_engines : ({args, meth}, cb) ->
    err = null
    for e in @engines when not err
      await meth.call e, args, defer(err)
    cb err

  #----------

  to_openpgp_packet : ( { tsec, passphrase } ) ->

  to_keybase_packet : ( { tsec, passphrase } ) ->

#=================================================================

exports.KeyBundle = KeyBundle
exports.Encryption = Encryption