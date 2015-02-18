
{KeyFetcher} = require './keyfetch'

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

  export_public : ( {asp, regen}, cb) -> cb EUI, null

  # If it can be used for sigs, regardless of whether there's a priv key
  can_verify : () -> false

#=================================================================================

exports.SignatureEngineInterface = class SignatureEngineInterface
  constructor : ({@km}) ->
  get_km : () -> @km
  box : (msg, cb) -> cb EUI
  unbox : (msb, cb) -> cb EUI

#=================================================================================


