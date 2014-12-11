
console.log "+ INC keymanager"
{KeyManagerInterface} = require '../kmi'
konst = require '../const'
C = konst.openpgp
K = konst.kb
{EdDSA} = require '../nacl/eddsa'
{SignatureEngine} = require './sigeng'
console.log "- INC keymanager"

#======================================================================

exports.KeyManager = class KeyManager extends KeyManagerInterface

  constructor : ({@key}) ->

  @generate : ({algo, params}, cb) ->
    algo or= EdDSA
    params or= {}
    await algo.generate params, defer err, key
    cb err, new KeyManager { key }

  #----------------------------------

  fetch : (key_ids, flags, cb) ->
    s = @key.ekid().toString('hex')
    key = null
    mask = C.key_flags.sign_data | C.key_flags.certify_keys | C.key_flags.auth
    if (s in key_ids) and (flags & mask) is flags
      key = @key
    else
      err = new Error "Key not found"
    cb err, key

  #----------------------------------

  get_keypair : () -> @key

  #----------------------------------

  eq : (km2) -> @key.eq(km2.key)

  #----------------------------------

  @import_public : ({hex, raw}, cb) ->
    err = ret = null
    if hex?
      raw = new Buffer hex, 'hex'
    [err, key] = EdDSA.parse_kb raw
    unless err?
      ret = new KeyManager { key }
    cb err, ret

  #----------------------------------

  check_public_eq : (km2) -> @eq(km2)

  #----------------------------------

  export_public : ({asp, regen}, cb) ->
    ret = @key.ekid().toString('hex')
    cb null, ret

  #----------------------------------

  make_sig_eng : () ->
    new SignatureEngine { km : @ }

#======================================================================

