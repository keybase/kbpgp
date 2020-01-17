kbpgp = require '../../'
{kb,KeyManager} = kbpgp
{bufferify,ASP} = require '../../lib/util'
{make_esc} = require 'iced-error'
util = require 'util'
{box} = require '../../lib/keybase/encode'
{Encryptor} = require 'triplesec'
{base91} = require '../../lib/basex'
example_keys = (require '../data/keys.iced').keys
C = require '../../lib/const'
ecc = require '../../lib/ecc/main'
{Message} = kbpgp.processor

asp = new ASP {}
bundle = null
userid = 'maxtaco@keybase.io'
master_passphrase = Buffer.from 'so long and thanks for all the fish', "utf8"
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

sanity_check = (T, bundle, cb) ->
  await bundle.primary.key.sanity_check defer err
  T.no_error err
  await bundle.subkeys[0].key.sanity_check defer err
  T.no_error err
  cb()

exports.step1_generate = (T,cb) ->
  await KeyManager.generate { asp, nbits : 1024, nsubs : 1, userid }, defer err, tmp
  bundle = tmp
  T.no_error err
  await sanity_check T, bundle, defer err
  cb()

exports.step2_salt_triplesec = (T, cb) ->
  tsenc = new Encryptor { key : master_passphrase, version : 3 }
  len = 12
  await tsenc.resalt { extra_keymaterial : len}, defer err, keys
  T.no_error err
  openpgp_pass = base91.encode keys.extra[0...len]
  T.waypoint "new OpenPGP password: #{openpgp_pass}"
  cb()

exports.step3_export_pgp_private = (T,cb) ->
  await bundle.sign { asp }, defer err
  T.no_error err
  unless err?
    passphrase = openpgp_pass
    await bundle.export_pgp_private { passphrase, asp }, defer err, msg
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

exports.step4a_test_failed_private_merge = (T,cb) ->
  await bundle.export_pgp_public {}, defer err, pub
  await KeyManager.import_from_armored_pgp { raw : pub }, defer err, b3
  T.no_error err
  await b3.merge_pgp_private { raw : pub }, defer err
  T.assert err?, "error came back"
  T.assert (err.toString().indexOf("no private key material found after merge") > 0), "the right error message"
  cb()

exports.step5_merge_pgp_private = (T,cb) ->
  await b2.merge_pgp_private { raw : pgp_private, asp }, defer err
  T.no_error err
  T.assert b2.has_pgp_private(), "b2 has a private half"
  T.assert b2.is_pgp_locked(), "b2 has a private half but is locked"
  bad_pass = "a" + openpgp_pass
  await b2.unlock_pgp { passphrase : bad_pass }, defer err
  T.assert err?, "we should have gotten an error when opening with a bad password"
  await b2.unlock_pgp { passphrase : openpgp_pass }, defer err
  T.no_error err
  T.assert (not b2.is_pgp_locked()), "unlocked b2 successfully"
  await sanity_check T, b2, defer err
  cb()

exports.step6_export_p3skb_private = (T,cb) ->
  await bundle.export_private_to_server { tsenc, asp }, defer err, p3skb
  T.no_error err
  await KeyManager.import_from_p3skb { raw : p3skb, asp }, defer err, tmp
  T.no_error err
  b3 = tmp
  T.assert b3.has_p3skb_private(), "b3 has keybase private part"
  T.assert b3.is_p3skb_locked(), "b3 is still locked"
  bad_pass = Buffer.concat [ master_passphrase, (Buffer.from "yo")]
  bad_tsenc = new Encryptor { key : bad_pass, version : 3 }
  await b3.unlock_p3skb { tsenc : bad_tsenc, asp }, defer err
  T.assert b3.is_p3skb_locked(), "b3 is still locked"
  T.assert err?, "failed to decrypt w/ bad passphrase"
  await b3.unlock_p3skb { tsenc, asp }, defer err
  T.no_error err
  T.assert (not b3.is_p3skb_locked()), "b3 is unlocked"
  await sanity_check T, b3, defer err
  compare_bundles T, bundle, b3
  T.no_error err
  cb()

exports.pgp_full_hash = (T,cb) ->
  now = Math.floor(new Date(2015, 9, 10)/1000)
  opts = { now }
  await KeyManager.import_from_armored_pgp { armored : example_keys.portwood, opts }, defer err, km
  T.no_error err
  await km.pgp_full_hash {}, defer err, hash
  T.no_error err
  T.assert hash == "5c31f2642b01d6beaf836999dafb54db59295a27a1e6e75665edc8db22691d90", "full hash doesn't match"
  cb()

exports.pgp_full_hash_nacl = (T,cb) ->
  km = null
  await kb.KeyManager.generate {}, T.esc(defer(km), cb)
  await km.pgp_full_hash {}, T.esc(defer(res), cb)
  T.assert not res?, "null value back"
  cb()

exports.change_key_and_reexport = (T, cb) ->
  esc = make_esc cb, "change_key_and_reexport"
  km = null
  F = C.openpgp.key_flags
  expire_in = 100
  args = {
    userid: "<test@example.org>"
    primary :
      algo: ecc.EDDSA
      flags : F.certify_keys | F.sign_data | F.auth
      expire_in : expire_in
    subkeys : [
      {
        flags : F.encrypt_storage | F.encrypt_comm
        expire_in : 0
        algo : ecc.ECDH
        curve_name : 'Curve25519'
      }
    ]
  }
  await KeyManager.generate args, esc defer km
  await km.sign {}, esc defer()
  await km.export_public {}, esc defer armored
  await KeyManager.import_from_armored_pgp { armored }, esc defer()

  # Extend expiration, resign, re-export, and try to import again.
  km.clear_pgp_internal_sigs()
  km.pgp.primary.lifespan.expire_in = 200
  km.pgp.subkeys[0].lifespan.expire_in = 100
  await km.sign {}, esc defer()
  await km.export_public { regen : true }, T.esc(defer(armored), cb)
  await KeyManager.import_from_armored_pgp { armored }, esc defer km2
  T.assert km2.primary._pgp.get_expire_time().expire_in is 200, "got correct expiration on primary"
  T.assert km2.subkeys[0]._pgp.get_expire_time().expire_in is 100, "got correct expiration on subkey"

  cb null

{Signature, EmbeddedSignature} = require '../../lib/openpgp/packet/signature'

exports.generate_key_default_hash = (T, cb) ->
  esc = make_esc cb
  F = C.openpgp.key_flags
  args = {
    userid: 'keymanager.iced test'
    primary: { flags: F.sign_data | F.certify_keys, algo : ecc.EDDSA }
    subkeys: [
      { flags: F.sign_data, algo : ecc.ECDSA }
      { flags: F.encrypt_storage | F.encrypt_conn, algo : ecc.ECDH, curve_name: 'NIST P-384' }
    ]
  }

  await KeyManager.generate args, esc defer km
  await km.sign {}, esc defer()
  await km.export_public {}, esc defer armored

  # Expect default hash to be SHA512
  hasher = kbpgp.hash.SHA512

  # Decode armored key, make sure the hasher is correct in
  # all signatures and embedded signatures.
  [err,msg] = kbpgp.armor.decode armored
  T.no_error err
  processor = new Message {}
  await processor.parse_and_inflate msg.body, esc defer()
  for pkt in processor.packets when pkt instanceof Signature
    T.equal pkt.hasher.klass, hasher.klass
    T.equal pkt.hasher.algname, hasher.algname
    T.equal pkt.hasher.type, hasher.type
    for subpkt in (pkt.unhashed_subpackets ? []) when subpkt instanceof EmbeddedSignature
      {sig} = subpkt
      T.equal sig.hasher.klass, hasher.klass
      T.equal sig.hasher.algname, hasher.algname
      T.equal sig.hasher.type, hasher.type

  cb null

exports.sign_key_with_hasher = (T, cb) ->
  esc = make_esc cb
  F = C.openpgp.key_flags
  args = {
    userid: 'keymanager.iced test'
    primary: { flags: F.sign_data | F.certify_keys, algo : ecc.EDDSA }
    subkeys: [
      { flags: F.sign_data, algo : ecc.ECDSA }
      { flags: F.encrypt_storage | F.encrypt_conn, algo : ecc.ECDH, curve_name: 'NIST P-384' }
    ]
  }

  hasher = kbpgp.hash.SHA1

  await KeyManager.generate args, esc defer km
  # Set hasher to SHA1 in primary key and subkeys.
  for key in [km.primary].concat(km.subkeys)
    key = km.pgp.key(key)
    T.assert key.hasher is null
    key.hasher = hasher
  # Signing should use SHA1 for self signature and subkey
  # signatures (as well as primary sigs from subkeys).
  await km.sign {}, esc defer()
  await km.export_public {}, esc defer armored

  # Decode armored key, make sure the hasher is correct in
  # all signatures and embedded signatures.
  [err,msg] = kbpgp.armor.decode armored
  T.no_error err
  processor = new Message {}
  await processor.parse_and_inflate msg.body, esc defer()
  for pkt in processor.packets when pkt instanceof Signature
    T.equal pkt.hasher.klass, hasher.klass
    T.equal pkt.hasher.algname, hasher.algname
    T.equal pkt.hasher.type, hasher.type
    for subpkt in (pkt.unhashed_subpackets ? []) when subpkt instanceof EmbeddedSignature
      {sig} = subpkt
      T.equal sig.hasher.klass, hasher.klass
      T.equal sig.hasher.algname, hasher.algname
      T.equal sig.hasher.type, hasher.type

  assert_pgp_hash = (hasher) ->
    if hasher.algname is 'SHA1'
      T.assert hasher.klass is kbpgp.hash.SHA1.klass
      T.equal hasher.type, 2
      new Error("signatures using SHA1 are not allowed")
  await KeyManager.import_from_armored_pgp { armored, opts: { assert_pgp_hash } }, defer err, km, warnings
  T.assert err?.message.indexOf("no valid primary key") >= 0
  T.assert not km?
  warns = warnings?.warnings() ? []
  T.equal warns.length, 3
  for v,i in [1,3,5]
    T.assert warns[i].match(new RegExp("^Signature failure in packet #{v}"))
    T.assert warns[i].indexOf("signatures using SHA1 are not allowed") >= 0


  cb null
