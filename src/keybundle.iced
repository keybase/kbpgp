{Single} = require './single'
{RSA} = require './rsa'
K = require('./const').kb
{make_esc} = require 'iced-error'
{unix_time,bufferify} = require './util'

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

class KeyWrapper
  constructor : ({@key, @generated, @expire_in}) ->

#=================================================================

class Subkey extends KeyWrapper
  constructor : ({key, @desc, generated, expire_in, @primary}) ->
    super { key, generated, expire_in }

#=================================================================

class Primary extends KeyWrapper
  constructor : ({key, generated, expire_in}) ->
    super { key, generated, expire_in }

#=================================================================

class Engine
  constructor : ({@primray, @subkeys, @userids}) ->
    @packets = []
    @messages = []
    @_allocate_key_pakets()

  _all_keys : () -> [ @primary ].concat @subkeys

  _allocate_key_packets : () ->
    for key in @_all_keys()
      @_v_allocate_key_packet key

  _self_sign_primary : ({asp}, cb) -> @_v_self_sign_primary { asp }, cb

#=================================================================

class PgpEngine extends Engine

  constructor : ({primary, subkeys, userids}) ->
    super { primary, subkeys, userids }

  _v_allocate_key_packet : (key) ->
    key._pgp = new opkts.KeyMaterial { key : key.key, timestamp : key.generated, userid : @userids.get_keybase() }

  userid_packet : () ->
    if not @_uidp
      @_uidp = new opkts.UserID @userids.get_keybase()
    @_uidp

  _v_self_sign_primary : ({asp}, cb) ->
    await @primary._pgp._self_sign_key { expire_in : @primary.expire_in, uidp : @userid_packet() }, defer err, @self_sign
    cb err, @self_sign

#=================================================================

class KeybaseEngine extends Engine

  constructor : ({primary, subkeys, userids}) ->
    super { primary, subkeys, userids }

  _v_allocate_key_packet : (key) ->
    key._keybase = new kpkts.Key { key : key.key, timestamp : key.generated, userid : @userids.get_keybase() }

  _self_sign_primary_key : ({asp}, cb) ->

  _v_self_sign_primary : ({asp}, cb) ->
    @packets.push @primary.

#=================================================================

class Bundle

  constructor : ({@primary, @subkeys, @userids}) ->
    @tsenc = null
    @pgp = new PgpEngine { @primary, @subkeys, @userids }
    @keybase = new KeybaseEngine { @primary, @subkeys, @userids }
    @engines = [ @pgp, @keybase ]

  #========================
  # Public Interface

  # Generate a new key bunlde from scratch.  Make the given number
  # of subkeys.
  @generate : ({asp, nsubs, userids }, cb) ->
    generated = unix_time()
    esc = make_esc cb, "Bundle::generate"
    asp.section "primary"
    await RSA.generate { asp, nbits: K.key_defaults.primary.nbits }, esc defer key
    primary = new Primary { key, generated, expire_in : K.key_defaults.primary.expire_in }
    subkeys = []
    expire_in = K.key_defaults.sub.expire_in
    for i in [0...nsubs]
      asp.section "subkey #{i+1}"
      await RSA.generate { asp, nbits: K.key_defaults.sub.nbits }, esc defer key
      subkeys.push new Subkey { key, desc : "subkey #{i}", primary, generated, expire_in }
    bundle = new Bundle { primary, subkeys, userids }

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

  #-----

  sign : ({asp}, cb) ->
    esc = make_esc "Bundle::_sign_pgp", cb
    await @_self_sign_primary { asp } , esc defer()
    for s in @subkeys
      await @_sign_subkey { s, asp } , esc defer()
    cb null

  # /Public Interface
  #========================
  
  _self_sign_primary : ({asp}, cb) ->
    @_apply_to_engines { asp, Engine.prototype._self_self_primary }, cb

  #----------

  _self_sign_primary_pgp : ({asp}, cb) ->
    uidp = new opkt.UserId @userids.get_keybase()
    @pgp.packets = [ @primary.pgp.public_framed(), uidp ]
    payload = Buffer.concat [ 
      @primary._pgp.to_signature_payload() 
    ]


  _sign_keybase : ({asp}, cb) ->

  to_openpgp_packet : ( { tsec, passphrase } ) ->

  to_keybase_packet : ( { tsec, passphrase } ) ->

#=================================================================

exports.Bundle = Bundle
exports.Encryption = Encryption