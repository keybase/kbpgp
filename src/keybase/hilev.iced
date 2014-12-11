
#
# A high-level interface to keybase-style signatures and encryptions,
# via the Keybase packet format, and the NaCl libraries.
#
#=================================================================================

{KeyManagerInterface} = require '../kmi'
{make_esc} = require 'iced-error'
encode = require './encode'
{asyncify,akatch} = require '../util'
konst = require '../const'
{alloc} = require './packet/alloc'
{Signature} = require './packet/signature'
{EdDSA} = require '../nacl/eddsa'
K = konst.kb
C = konst.openpgp

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

#=================================================================================

exports.unbox = unbox = ({armored,rawobj}, cb) ->
  esc = make_esc cb, "unbox"

  if not armored? and not rawobj?
    await athrow (new Error "need either 'armored' or 'rawobj'"), esc defer()

  if armored?
    buf = new Buffer armored, 'base64'
    await akatch ( () -> encode.unseal buf), esc defer rawobj

  await asyncify alloc(rawobj), esc defer packet
  await packet.unbox esc defer res
  res.km = new KeyManager { key : res.keypair }

  cb null, res

#=================================================================================

exports.box = box = ({msg, sign_with}, cb) ->
  esc = make_esc cb, "box"
  await Signature.box { km : sign_with, payload : msg }, esc defer packet
  packed = packet.frame_packet()
  sealed = encode.seal { obj : packed, dohash : false }
  armored = sealed.toString('base64')
  cb null, armored

#=================================================================================

exports.SignatureEngine = class SignatureEngine

  #-----

  constructor : ({@km}) ->
  get_km      : -> @km

  #-----

  box : (msg, cb) ->
    esc = make_esc cb, "SignatureEngine::box"
    await box { msg, sign_with : @km }, esc defer armored
    out = { type : "kb", armored, kb : armored }
    cb null, out

  #-----

  unbox : (msg, cb) ->
    esc = make_esc cb, "SignatureEngine::unbox"
    err = payload = null
    await unbox { armored : msg }, esc defer res
    if not res.km.eq @km
      a = res.km.get_ekid().toString('hex')
      b = @km.get_ekid().toString('hex')
      err = new Error "Got wrong signing key: #{a} != #{b}"
    else
      payload = res.payload
    cb null, payload

#=================================================================

module.exports = { box, unbox, KeyManager }
