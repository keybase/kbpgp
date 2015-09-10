
{KeyFetcher} = require './keyfetch'
{make_esc} = require 'iced-error'

#
# KeyManagerInterface
#
#   We have two types of KeyManagers: openpgp.KeyManager and kb.KeyManager
#   They share some functionality and in some places can be used interchangably.
#   We specify the interface here.
#

EUI = new Error "not implemented"

#=================================================================================

exports.KeyManagerInterface = class KeyManagerInterface extends KeyFetcher

  constructor : () ->

  # will only return non-null for PGP
  get_pgp_fingerprint : () -> null

  # Works for any type of key
  get_ekid : () -> null

  # Work for any type of key, will give the familiar PGP fingerprint for
  # PGP or the URL-base64-full key for NACL keys.
  get_fp2 : () -> null
  get_fp2_formatted : () -> null

  # Either 'pgp' or 'kb'
  get_type : () -> null

  # Check equality of public halves, recursively down to subkeys
  # if necessary
  check_public_eq : (km2) -> @EUI

  # Get which userIDS are signed into the key
  get_userids : () -> []

  # Get the primary keypair for PGP, or just the keypair for KB keys
  # Return a BaseKeyPair
  get_primary_keypair : () -> null

  # Get all keymaterial packets associate with this key.
  # returns a list of <openpgp.packet.KeyMaterial,bool> pairs,
  # where the bool indicates if it's the primary or not.  Will be
  # empty for Keybase keys
  get_all_pgp_key_materials : () -> []

  # UserIDS signed into the key, will be empty for KB keys
  get_userids_mark_primary : () -> []

  # Make a signature engine from this object
  make_sig_eng : () -> null

  # Get an ASCII-armored version of the PGP key, if any
  export_pgp_public : (opts, cb) -> cb null, null
  export_pgp_private : (opts, cb) -> cb null, null

  export_public : ( {asp, regen}, cb) -> cb EUI, null
  export_private : ( {asp, passphrase, p3skb}, cb) -> cb EUI

  # If it can be used for sigs, regardless of whether there's a priv key
  can_verify : () -> false

  # like can_verify() but also has a private key
  can_sign : () -> false

  # If it can be used for encryption
  can_encrypt : () -> false

  # Like can_decrypt(), and also has a private key
  can_decrypt : () -> false

  # Get all PGP key ids returns all of the PGP key IDs found in this
  # key manager.  For NaCl keys, it's empty.
  get_all_pgp_key_ids : () -> []

  # Returns non-null for PGP KMs
  pgp_full_hash : (opts, cb) -> cb null, null

#=================================================================================

exports.SignatureEngineInterface = class SignatureEngineInterface
  constructor : ({@km}) ->
  get_km : () -> @km
  box : (msg, cb) -> cb EUI
  unbox : (msb, cb) -> cb EUI

  get_body : ({armored}, cb) -> cb EUI
  get_unverified_payload_from_raw_sig_body : ({body}, cb) -> cb EUI

  get_body_and_unverified_payload : ({armored}, cb) ->
    esc = make_esc cb, "get_body_and_unverified_payload"
    await @get_body {armored}, esc defer body
    await @get_unverified_payload_from_raw_sig_body { body}, esc defer payload
    cb null, body, payload

#=================================================================================


