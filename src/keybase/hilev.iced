
#
# A high-level interface to keybase-style signatures and encryptions,
# via the Keybase packet format, and the NaCl libraries.
#
#=================================================================================

{SignatureEngineInterface,KeyManagerInterface} = require '../kmi'
{make_esc} = require 'iced-error'
encode = require './encode'
{athrow,bufferify,base64u,buffer_xor,asyncify,akatch} = require '../util'
konst = require '../const'
{alloc} = require './packet/alloc'
{Signature} = require './packet/signature'
{Encryption} = require './packet/encryption'
{EdDSA} = require '../nacl/eddsa'
{errors} = require '../errors'
{DH} = require '../nacl/dh'
K = konst.kb
C = konst.openpgp

#======================================================================

class KeyManager extends KeyManagerInterface

  constructor : ({@key, @server_half}) ->

  @generate : ({algo, seed, split, server_half, klass}, cb) ->
    algo or= EdDSA
    klass or= KeyManager
    await algo.generate {split, seed, server_half}, defer err, key, server_half
    cb err, new klass { key, server_half }

  #----------------------------------

  get_mask : () -> (C.key_flags.sign_data | C.key_flags.certify_keys | C.key_flags.auth)

  #----------------------------------

  fetch : (key_ids, flags, cb) ->
    s = @key.ekid().toString('hex')
    key = null
    mask = @get_mask()
    if (s in key_ids) and (flags & mask) is flags
      key = @key
    else
      err = new Error "Key not found"
    cb err, key

  #----------------------------------

  get_keypair : () -> @key
  get_primary_keypair : () -> @key
  can_verify : () -> true
  can_sign : () -> @key?.can_sign()

  #----------------------------------

  eq : (km2) -> @key.eq(km2.key)

  #----------------------------------

  @import_private : ({hex, raw}, cb) ->
    err = ret = null
    if hex?
      try
        raw = Buffer.from hex, 'hex'
      catch e
        return cb e
    await EdDSA.import_private { raw }, defer err, key
    ret = new KeyManager { key } unless err?
    cb err, ret

  #----------------------------------

  @import_public : ({hex, raw}, cb) ->
    err = ret = null
    if hex?
      try
        raw = Buffer.from hex, 'hex'
      catch e
        return cb e
    [err, key] = EdDSA.parse_kb raw
    if err?
      await EncKeyManager.import_public { raw }, defer err, ret
    else
      ret = new KeyManager { key }
    cb err, ret

  #----------------------------------

  check_public_eq : (km2) -> @eq(km2)

  #----------------------------------

  export_public : ({asp, regen}, cb) ->
    ret = @key.ekid().toString('hex')
    cb null, ret

  #----------------------------------

  export_private : ({asp, p3skb, passphrase}, cb) ->
    err = res = null
    if p3skb
      err = new Error "No support yet for P3SKB encrypted secret key exports"
    else
      await @key.export_secret_key_kb {}, defer err, res
    cb err, res

  #----------------------------------

  export_server_half : () -> @server_half?.toString 'hex'

  #----------------------------------

  get_ekid : () -> return @get_keypair().ekid()
  get_fp2 : () -> @get_ekid()
  get_fp2_formatted : () -> base64u.encode @get_fp2()
  get_type : () -> "kb"

  #----------------------------------

  make_sig_eng : () -> new SignatureEngine { km : @ }

  #----------------------------------

  verify_raw : ({sig, payload, prefix}, cb) ->
    (new Signature { key : @key?.ekid(), payload, prefix, sig, detached : true }).verify cb

#=================================================================================


class EncKeyManager extends KeyManager

  #----------------------------------

  @generate : (params, cb) ->
    params.algo = DH
    params.klass = EncKeyManager
    KeyManager.generate params, cb

  #----------------------------------

  make_sig_eng : () -> null
  can_sign : () -> false
  can_verify : () -> false
  can_encrypt : () -> true
  can_decrypt : () -> @key?.priv?

  #----------------------------------

  @import_private : ({hex, raw}, cb) ->
    err = ret = null
    if hex?
      try
        raw = Buffer.from hex, 'hex'
      catch e
        return cb e
    await EncKeyManager.generate { seed : raw  }, defer err, km
    cb err, km

  #----------------------------------

  get_mask : () -> (C.key_flags.encrypt_comm | C.key_flags.encrypt_storage )

  #----------------------------------

  @import_public : ({hex, raw}, cb) ->
    err = ret = null
    if hex?
      try
        raw = Buffer.from hex, 'hex'
      catch e
        return cb e
    [err, key] = DH.parse_kb raw
    unless err?
      ret = new EncKeyManager { key }
    cb err, ret

#=================================================================================

unbox_decode = ({armored,binary,rawobj,require_packet_hash}) ->
  err = ret = null
  if not armored? and not rawobj? and not binary?
    err = new Error "need either 'armored' or 'binary' or 'rawobj'"
    return [ err, null ]
  if armored?
    binary = Buffer.from armored, 'base64'
  if binary?
    try
      rawobj = encode.unseal binary, { strict : require_packet_hash }
    catch e
      return [e, null]
  [err, ret] = alloc rawobj
  return [err, ret, binary]

#=================================================================================

unbox = ({armored,binary,rawobj,encrypt_for,prefix,require_packet_hash}, cb) ->
  esc = make_esc cb, "unbox"

  await asyncify unbox_decode({armored,binary,rawobj,require_packet_hash}), esc defer packet, binary
  packet.prefix = prefix if prefix? # can specify the prefix out-of-band (it'll stomp over us)
  await packet.unbox {encrypt_for}, esc defer res

  if res.keypair?
    res.km = new KeyManager { key : res.keypair }
  if res.sender_keypair?
    res.sender_km = new KeyManager { key : res.sender_keypair }
  if res.receiver_keypair?
    res.receiver_km = new KeyManager { key : res.receiver_keypair }

  cb null, res, binary

#=================================================================================

box = ({msg, sign_with, encrypt_for, anonymous, nonce, prefix, dohash}, cb) ->
  esc = make_esc cb, "box"
  msg = bufferify msg
  if encrypt_for?
    await Encryption.box { sign_with, encrypt_for, plaintext : msg, anonymous, nonce }, esc defer packet
  else
    await Signature.box { km : sign_with, payload : msg, prefix }, esc defer packet
  packed = packet.frame_packet()
  dohash or= false
  sealed = encode.seal { obj : packed, dohash }
  armored = sealed.toString('base64')
  cb null, armored, sealed, packet.sig

#=================================================================================

verify = ({armored, binary, kid, require_packet_hash }, cb) ->
  esc = make_esc cb
  err = null
  await KeyManager.import_public { hex : kid }, esc defer km
  await unbox { armored, binary, require_packet_hash }, esc defer res
  unless res.km.check_public_eq(km)
    err = new errors.WrongSigningKeyError "Got wrong signing key"
  cb err, res.payload

#=================================================================================

get_sig_body = ({armored}) ->
  [ err, decoded ] = decode_sig {armored}
  return [ err, decoded?.body ]

# Designed to have similar output to kbpgp.armor.decode(). NOTE that this is
# different from pgp-utils.armor.decode(), where @type is a string.
decode_sig = ({armored}) ->
  decoded = {
    body: Buffer.from armored, 'base64'
    type: C.message_types.generic
    payload: armored
  }
  return [ null, decoded ]

#=================================================================================

class SignatureEngine extends SignatureEngineInterface

  #-----

  constructor : ({@km}) ->
  get_km      : -> @km

  #-----

  get_unverified_payload_from_raw_sig_body : ({body, require_packet_hash}, cb) ->
    esc = make_esc cb, "get_payload_from_raw_sig_body"
    await akatch ( () -> encode.unseal body, { strict : require_packet_hash} ), esc defer rawobj
    await asyncify alloc(rawobj), esc defer packet
    cb null, packet.payload

  #-----

  get_body : (args, cb) ->
    [ err, res ] = get_sig_body(args, cb)
    cb err, res

  #-----

  box : (msg, cb, {prefix, dohash} = {}) ->
    esc = make_esc cb, "SignatureEngine::box"
    await box { msg, prefix, sign_with : @km, dohash }, esc defer armored, raw, sig
    out = { type : "kb", armored, kb : armored, raw, sig }
    cb null, out

  #-----

  unbox : (msg, cb, opts = {}) ->
    esc = make_esc cb, "SignatureEngine::unbox"
    err = payload = null
    arg = if Buffer.isBuffer(msg) then { binary : msg }
    else { armored : msg }
    arg.prefix = opts.prefix
    arg.require_packet_hash = opts.require_packet_hash
    await unbox arg, esc defer res, binary
    if not res.km.eq @km
      a = res.km.get_ekid().toString('hex')
      b = @km.get_ekid().toString('hex')
      err = new errors.WrongSigningKeyError "Got wrong signing key"
    else
      payload = res.payload
    cb err, payload, binary

#=================================================================

module.exports = { box, unbox, unbox_decode, KeyManager, EncKeyManager, decode_sig, get_sig_body, encode, verify}
