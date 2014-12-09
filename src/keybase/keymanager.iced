
{KeyFetcher} = require '../keyfetch'
konst = require '../const'
C = konst.openpgp
K = konst.kb
{EdDSA} = require '../nacl/eddsa'

#======================================================================

exports.KeyManager = class KeyManager extends KeyFetcher

  constructor : ({@key}) ->

  @generate : ({algo, params}, cb) ->
    algo or= EdDSA
    params or= {}
    await algo.generate params, defer err, key
    cb err, new KeyManager { key }

  fetch : (key_ids, flags, cb) ->
    s = @key.ekid().toString('hex')
    key = null
    mask = C.key_flags.sign_data | C.key_flags.certify_keys | C.key_flags.auth
    if (s in key_ids) and (flags & mask) is flags
      key = @key
    else
      err = new Error "Key not found"
    cb err, key

  get_keypair : () -> @key

  eq : (km2) -> @key.eq(km2.key)

#======================================================================

