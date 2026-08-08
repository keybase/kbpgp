kbpgp = require '../..'
{KeyManager} = kbpgp
C = require('../../lib/const').openpgp
{decode,encode} = require '../../lib/openpgp/armor'

exports.malformed_gnu_extension = (T, cb) ->
  await KeyManager.generate { userid : "s2k@test.com", nbits : 1024, nsubs : 1 }, T.esc(defer(km), cb)
  await km.sign {}, T.esc(defer(), cb)

  # Force private export to encode this subkey with GNU dummy S2K.
  km.subkeys[0].key.priv = null
  await km.export_pgp_private {}, T.esc(defer(armored), cb)

  [err, msg] = decode armored
  T.no_error err

  # Corrupt extension name in the buffer.
  body = Buffer.from msg.body
  marker = Buffer.from "GNU", "utf8"
  i = body.indexOf marker
  T.assert i >= 0, "found GNU dummy S2K marker"
  body[i] = "X".charCodeAt 0

  corrupted = encode C.message_types.private_key, body
  await KeyManager.import_from_armored_pgp { raw : corrupted }, defer err
  T.assert err?
  T.equal err?.name, "Error"
  T.equal err?.message, "Malformed GNU-extension: XNU"
  cb()
