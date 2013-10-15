{Single} = require './single'
{RSA} = require './rsa'
K = require('./const').kb
{make_esc} = require 'iced-error'

#=================================================================

class Encryption 
  constructor : ({@tsenc, @passphrase}) ->

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

  @import_from_armored_pgp_private : ({raw, passphrase, asp}, cb) ->

  @import_from_armored_pgp_public : ({raw, asp}, cb) ->

  # The export consists of
  #   1. A PGP message (potentially redacted from upload)
  #   2. A keybase message (Public key only)
  export_to_server_public_only : ({asp}, cb) ->

  # A private export consists of:
  #   1. The redacted PGP message
  #   2. The keybase message (Public and private keys)
  export_to_server_private : ({asp}, cb) ->

  # Export to a PGP PRIVATE KEY BLOCK, stored in PGP format
  # We'll need to reencrypt with a derived 
  export_to_client : (cb) ->

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