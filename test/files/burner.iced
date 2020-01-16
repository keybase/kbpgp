kbpgp = require '../../'
{KeyManager} = kbpgp
{make_esc} = require 'iced-error'

{OnePassSignature} = require '../../lib/openpgp/packet/one_pass_sig'
{Literal} = require '../../lib/openpgp/packet/literal'
{Signature, CreationTime, Issuer} = require '../../lib/openpgp/packet/signature'

C = kbpgp.const.openpgp
{ecc, hash, armor} = kbpgp
{Message} = kbpgp.processor

km = null

exports.init = (T, cb) ->
  esc = make_esc cb
  F = C.key_flags
  keygen_arg = {
    userid: "burner.iced test"
    primary: { flags: F.sign_data | F.certify_keys, algo : ecc.EDDSA }
    subkeys: [{ flags: F.encrypt_storage | F.encrypt_conn, algo : ecc.ECDH, curve_name: 'NIST P-384' }]
  }
  await KeyManager.generate keygen_arg, esc defer km
  cb null

exports.burn_with_hasher = (T, cb) ->
  esc = make_esc cb

  msg_plain = 'hello world\n'

  sig_eng = km.make_sig_eng()
  await sig_eng.box msg_plain, esc(defer(res)), { hasher: hash.SHA1 }
  pgp_res = res.pgp

  # Parse the message back
  msg = new Message {}
  await msg.parse_and_inflate res.raw, esc defer()

  T.equal msg.packets.length, 3
  # Except the following packet types
  for typ, index in [OnePassSignature, Literal, Signature]
    T.assert (p = msg.packets[index]) instanceof typ
    # Check if OnePassSignature and Signature have the correct hasher.
    if index in [0, 2]
      T.equal p.hasher.algname, 'SHA1'
      T.equal p.hasher.type, 2
      T.equal p.hasher.klass, hash.SHA1.klass

  # Try to verify the message
  sig_eng = km.make_sig_eng()
  await sig_eng.unbox pgp_res, esc defer res
  T.equal res.toString(), msg_plain

  assert_pgp_hash = (hasher) ->
    if hasher.algname is 'SHA1' then new Error 'found sha1 hash'
  await sig_eng.unbox pgp_res, (defer err, res), { assert_pgp_hash }
  T.equal err?.message, 'found sha1 hash'
  T.assert not res?

  cb null

unpack_pgp_message = ({raw, armored}, cb) ->
  esc = make_esc cb
  if armored?
    [err,msg] = armor.decode armored
    if err then return cb err
    raw = msg.body
  msg = new Message {}
  await msg.parse_and_inflate raw, esc defer()
  cb null, msg

assert_hasher = ({T, msg, hasher, tag}) ->
  for p in msg.packets when p.hasher?
    T.equal p.hasher.algname, hasher.algname, "wrong hasher at #{tag}"
    T.equal p.hasher.type, hasher.type
    T.equal p.hasher.klass, hasher.klass

exports.burn_with_hasher_2 = (T, cb) ->
  # However, there are more ways to burn a message.
  esc = make_esc cb

  hasher = hash.SHA256
  msg_plain = 'but the future refused to change'

  await kbpgp.burn { msg: msg_plain, sign_with: km, opts: { hasher } }, esc defer res
  await unpack_pgp_message { T, armored: res }, esc defer msg
  assert_hasher { T, msg, hasher, tag: 'generic' }

  await kbpgp.clearsign { msg: msg_plain, signing_key: km.primary._pgp, hasher }, esc defer res
  await unpack_pgp_message { T, armored: res }, esc defer msg
  assert_hasher { T, msg, hasher, tag: 'clear' }

  # To pass hasher to detachsign, use `hash_streamer`.
  hash_streamer = hash.streamers.SHA256()
  hash_streamer.update Buffer.from msg_plain
  await kbpgp.detachsign { signing_key: km.primary._pgp, hash_streamer }, esc defer res
  await unpack_pgp_message { T, armored: res }, esc defer msg
  assert_hasher { T, msg, hasher, tag: 'detach' }

  cb null

exports.burner_default_hash = (T, cb) ->
  # Make sure there are reasonable defaults when hasher is not specified.
  esc = make_esc cb

  msg_plain = 'hell world\n\n'
  sig_eng = km.make_sig_eng()
  await sig_eng.box msg_plain, esc defer res

  msg = new Message {}
  await msg.parse_and_inflate res.raw, esc defer()

  T.equal msg.packets.length, 3
  for typ, index in [OnePassSignature, Literal, Signature]
    T.assert (p = msg.packets[index]) instanceof typ
    if index in [0, 2]
      T.equal p.hasher.algname, 'SHA512'
      T.equal p.hasher.type, 10
      T.equal p.hasher.klass, hash.SHA512.klass

  cb null

exports.assert_pgp_hash = (T, cb) ->
  # Test assert_pgp_hash with different message types.
  esc = make_esc cb
  hasher = hash.MD5
  msg_plain = 'Could a machine think? Could the mind itself be a thinking machine?'

  sig_eng = km.make_sig_eng()

  assert_pgp_hash = (hasher) ->
    if (hn = hasher.algname) in ['SHA1', 'MD5']
      new Error "found insecure #{hn} hash"

  # Generic messages are already tested in `burn_with_hasher` test
  # through `unbox` API.

  await kbpgp.clearsign { msg: msg_plain, signing_key: km.primary._pgp, hasher }, esc defer res
  [err,decoded] = armor.decode res
  T.no_error err
  msg = new Message { keyfetch: km, assert_pgp_hash }
  await msg.parse_and_process decoded, defer err
  T.equal err?.message, "found insecure MD5 hash"

  hash_streamer = hash.streamers.SHA1()
  hash_streamer.update Buffer.from msg_plain
  await kbpgp.detachsign { signing_key: km.primary._pgp, hash_streamer }, esc defer res
  [err,decoded] = armor.decode res
  T.no_error err
  msg = new Message { keyfetch: km, assert_pgp_hash, data: Buffer.from(msg_plain) }
  await msg.parse_and_process decoded, defer err
  T.equal err?.message, "found insecure SHA1 hash"

  cb null
