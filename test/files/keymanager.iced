{KeyManager} = require '../../src/keymanager'
{bufferify,ASP} = require '../../src/util'
{make_esc} = require 'iced-error'
util = require 'util'
{box} = require '../../src/keybase/encode'
{Encryptor} = require 'triplesec'
{base91} = require '../../src/basex'

asp = new ASP {}
bundle = null
userid = 'maxtaco@keybase.io'
master_passphrase = new Buffer 'so long and thanks for all the fish', "utf8"
tsenc = null
openpgp_pass = null
pgp_private = null
b2 = null
b3 = null

compare_keys = (T, k1, k2, what) ->
  T.equal k1.ekid().toString('hex'), k2.ekid().toString('hex'), "#{what} keys match"
compare_bundles = (T, b1, b2) ->
  compare_keys T, b1.primary, b2.primary, "primary"
  compare_keys T, b1.subkeys[0], b2. subkeys[0], "subkeys[0]"

sanity_check = (T, bundle) ->
  T.no_error bundle.primary.key.sanity_check()
  T.no_error bundle.subkeys[0].key.sanity_check()

exports.step1_generated = (T,cb) ->
  await KeyManager.generate { asp, nbits : 1024, nsubs : 1, userid }, defer err, tmp
  bundle = tmp
  T.no_error err
  sanity_check T, bundle
  cb()

exports.step2_salt_triplesec = (T, cb) ->
  tsenc = new Encryptor { key : master_passphrase, version : 2 }
  len = 12
  await tsenc.resalt { extra_keymaterial : len}, defer keys
  openpgp_pass = base91.encode keys.extra[0...len]
  T.waypoint "new OpenPGP password: #{openpgp_pass}"
  cb()

exports.step3_export_pgp_private = (T,cb) ->
  await bundle.sign { asp }, defer err
  T.no_error err
  unless err?
    passphrase = openpgp_pass
    await bundle.export_pgp_private_to_client { passphrase, asp }, defer err, msg
    T.no_error err
  unless err?
    T.waypoint "Generated new PGP Private key: #{msg.split(/\n/)[0...2].join(' ')}"
    pgp_private = msg
  cb()

exports.step4_import_pgp_public = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : pgp_private, asp, userid}, defer err, tmp
  b2 = tmp
  T.no_error err
  unless err?
    compare_bundles T, bundle, b2
  cb()

exports.step5_merge_pgp_private = (T,cb) ->
  await b2.merge_pgp_private { raw : pgp_private, asp }, defer err
  T.no_error err
  bad_pass = "a" + openpgp_pass 
  await b2.open_pgp { passphrase : bad_pass }, defer err
  T.assert err?, "we should have gotten an error when opening with a bad password"
  await b2.open_pgp { passphrase : openpgp_pass }, defer err
  T.no_error err
  sanity_check T, b2
  cb()

exports.step6_export_keybase_private = (T,cb) ->
  await bundle.export_private_to_server { tsenc, asp }, defer err, {keybase}
  T.no_error err
  await KeyManager.import_from_packed_keybase { raw : keybase, asp }, defer err, tmp
  T.no_error err
  b3 = tmp
  bad_pass = Buffer.concat [ master_passphrase, (new Buffer "yo")]
  bad_tsenc = new Encryptor { key : bad_pass, version : 2 }
  await b3.open_keybase { tsenc : bad_tsenc, asp }, defer err
  T.assert err?, "failed to decrypt w/ bad passphrase"
  await b3.open_keybase { tsenc, asp }, defer err
  T.no_error err
  sanity_check T, b3
  compare_bundles T, bundle, b3
  T.no_error err
  cb()
