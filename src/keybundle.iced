{Single} = require './single'
{RSA} = require './rsa'
K = require('./const').kb
{make_esc} = require 'iced-error'
{bufferify} = require './util'

#=================================================================

class Encryption 
  constructor : ({@tsenc, passphrase}) ->
    @passphrase = bufferify passphrase
    @tsenc or= new triplesec.Encryptor { version : 2, @passphrase }

#=================================================================

class UserIds
  constructor : ({@openpgp, @keybase}) ->
    @openpgp or= "#{@keybase}@keybase.io"

#=================================================================

class KeyWrapper
  constructor : ({@key, @generated, @expires}) ->

#=================================================================

class Subkey extends KeyWrapper
  constructor : ({key, @desc, generated, expires}) ->
    super { key, generated, expires }

#=================================================================

class Primary extends KeyWrapper
  constructor : ({key, generated, expires}) ->
    super { key, generated, expires }

#=================================================================

class Bundle

  constructor : ({@primary, @subkeys, @userids}) ->
    @tsenc = null

  #========================
  # Public Interface

  # Generate a new key bunlde from scratch.  Make the given number
  # of subkeys.
  @generate : ({asp, nsubs, userids }, cb) ->
    esc = make_esc cb, "Bundle::generate"
    asp.section "primary"
    await RSA.generate { asp, nbits: K.key_defaults.primary.nbits }, esc defer primary
    subkeys = []
    for i in [0...nsubs]
      asp.section "subkey #{i+1}"
      await RSA.generate { asp, nbits: K.key_defaults.sub.nbits }, esc defer key
      subkeys.push new Subkey { key, desc : "subkey #{i}" }
    ring = new Bundle { primary, subkeys, userids }
    cb null, ring

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

  # Open the private MPIs of the secret key, and check for sanity.
  # Use the given triplesec.Encryptor / password object.
  open_keybase : ({asp}, cb) ->

  # The export consists of
  #   1. A PGP message (potentially redacted from upload)
  #   2. A keybase message (Public key only)
  export_public_to_server : ({asp}, cb) ->

  # A private export consists of:
  #   1. The redacted PGP message
  #   2. The keybase message (Public and private keys)
  export_private_to_server : ({asp}, cb) ->

  # Export to a PGP PRIVATE KEY BLOCK, stored in PGP format
  # We'll need to reencrypt with a derived key
  export_pgp_private_to_client : ({asp}, cb) ->

  # Export the PGP PUBLIC KEY BLOCK stored in PGP format
  # to the client...
  export_pgp_public_to_client : ({asp}, cb) ->

  # /Public Interface
  #========================
  
  sign_pgp : ({asp}, cb) ->

  sign_keybase : ({asp}, cb) ->

  sign : ({asp}, cb) ->
    esc = make_esc cb, "Bundle::generate"
    await @sign_pgp { asp }, esc defer()
    await @sign_keybase { asp }, esc defer()
    cb null


  to_openpgp_packet : ( { tsec, passphrase } ) ->

  to_keybase_packet : ( { tsec, passphrase } ) ->

#=================================================================


#=================================================================

exports.Bundle = Bundle
exports.Encryption = Encryption