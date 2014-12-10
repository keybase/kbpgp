
{KeyBlock} = require '../../lib/openpgp/processor'
{parse} = require '../../lib/openpgp/parser'
armor = require '../../lib/openpgp/armor'
C = require '../../lib/const'
util = require 'util'
{ASP} = require '../../lib/util'
{KeyManager} = require '../../'
{keys} = require('../data/keys.iced')

#============================================================================

exports.public_keys_advanced = (T,cb) ->
  names = [ "edbett", "azet", "bitfolk", "ophelia", "sneak", "elitehaxor", "gmax",
            "finn", "adam", "ry4an", "asymptotic", "dbellizzi", "fincham",
            "thierry", "babazka", "zyphlar", "grantolson", "vanity" ]
  for n in names
    await KeyManager.import_from_armored_pgp { raw : keys[n] } , defer err, km, warnings
    T.no_error err
    T.assert km, "a key manager came back"
    if err?
      console.log "Failed on #{n} --->"
      console.log keys[n]
      throw err
    T.waypoint "parsed #{n}"
  cb()

#============================================================================

exports.decode_pgp_secret_key_1 = (T,cb) ->
  skey = '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'
  passphrase = "catsdogs"
  [err, packets] = parse (new Buffer skey, 'base64')
  T.no_error err
  T.waypoint "parsed"
  processor = new KeyBlock packets
  await processor.process defer err
  T.no_error err
  T.waypoint "signatures verified"
  n = 0
  for p,i in packets when p.is_key_material()
    n++
    await p.unlock { passphrase }, defer err
    T.no_error err
    await p.key.sanity_check defer err
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

exports.public_key_round_trip = (T,cb) ->

  raw = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.20 (Darwin)
Comment: GPGTools - http://gpgtools.org

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
nMd8vYZjDx7ro+5buf2cPmeiYlJdKQ==
=UGvW
-----END PGP PUBLIC KEY BLOCK-----
"""

  userid = "max@keybase.io"
  asp = new ASP {}
  await KeyManager.import_from_armored_pgp { asp, raw, userid }, defer err, b1
  T.no_error err
  await b1.sign {asp}, defer err
  T.no_error err
  await b1.export_pgp_public {asp, regen : true}, defer err, raw
  T.no_error err
  await KeyManager.import_from_armored_pgp { asp, raw, userid }, defer err, b2
  T.no_error err
  T.equal b1.primary.ekid().toString('hex'), b2.primary.ekid().toString('hex'), "primary keys match"
  T.equal b1.subkeys[0].ekid().toString('hex'), b2.subkeys[0].ekid().toString('hex'), "subkeys match"
  cb()

#============================================================================

exports.public_key_with_multiple_signers = (T,cb) ->

  raw = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

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
Dx7ro+5buf2cPmeiYlJdKQ==
=58Xp
-----END PGP PUBLIC KEY BLOCK-----
"""
  await KeyManager.import_from_armored_pgp { raw},  defer err, kb, warnings
  T.no_error err
  T.assert kb, "kb came back ok"
  v = warnings.warnings()
  expected_warnings = [
    "Skipping signature by another issuer: fbc07d6a97016cb3 != 63847b4b83930f0c"
    "Skipping signature by another issuer: 47484e50656d16c7 != 63847b4b83930f0c"
  ]
  T.equal v, expected_warnings, "warnings were right"
  cb()

#============================================================================

exports.public_key_with_pic = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.with_pic_1 } , defer err, km
  T.no_error err
  T.equal km.user_attributes?.length, 1, "We got a picture out, as expected"
  T.assert km.user_attributes?[0]?.data?, "..with actual picture data"
  cb()

#============================================================================

exports.public_key_expired_uid = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.expired_uid } , defer err, km, warnings
  T.assert (err?), "should get an error"
  T.equal err.message, "no valid primary key self-signature", "the right error"
  cb()

#============================================================================

exports.public_key_expired_subkey = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.expired_subkey } , defer err, km, warnings
  T.no_error err # it's not an error to lack subkeys
  T.assert warnings.warnings()[0].match /^Signature failure in packet 3: Key expired (\d+)s ago$/
  T.equal warnings.warnings()[1], "Subkey 0 was invalid; discarding", "the right warning"
  T.equal km.subkeys.length, 0, "didn't get any valid subkeys in the key manager"
  cb()

#============================================================================

exports.public_key_expired_both = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.expired_both } , defer err, km, warnings
  T.assert (err?), "should get an error"
  T.equal err.message, "no valid primary key self-signature", "the right error"
  T.equal warnings.warnings().length, 2, "failed two checks"
  cb()

#============================================================================
