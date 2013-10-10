
{Processor} = require '../../lib/packet/processor'
{parse} = require '../../lib/packet/parser'
armor = require '../../lib/encode/armor'
C = require '../../lib/const'

#============================================================================

exports.decode_pgp_secret_key_1 = (T,cb) ->
  skey = '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'
  passphrase = "catsdogs"
  [err, packets] = parse (new Buffer skey, 'base64')
  T.no_error err
  T.waypoint "parsed"
  processor = new Processor packets
  await processor.verify_signatures defer err
  T.no_error err
  T.waypoint "signatures verified"
  n = 0
  for p,i in packets when p.is_key_material()
    n++
    await p.open { passphrase }, defer err
    T.no_error err
    err = p.key.sanity_check()
    T.waypoint "opened key #{i}"
    T.no_error err
    T.waypoint "sanity checked key #{i}"
  T.equal n, 2, "need 2 keys"
  cb()

#============================================================================

armored = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.20 (Darwin)
Comment: GPGTools - http://gpgtools.org

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
ObMKV7f7yqGEQNpyrXlHl4qGSzkvgxQ6IzTA1g==
=DRiu
-----END PGP PRIVATE KEY BLOCK-----"""

#-----------------------

exports.dearmor = (T,cb) ->
  [err, m] = armor.decode armored
  T.no_error err
  T.equal m.type, C.openpgp.message_types.private_key, "type is correct"
  cb()

#============================================================================

