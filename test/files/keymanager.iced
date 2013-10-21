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

compare_keys = (T, k1, k2, what) ->
  T.equal k1.ekid().toString('hex'), k2.ekid().toString('hex'), "#{what} keys match"

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
    compare_keys T, bundle.primary, b2.primary, "primary keys"
    compare_keys T, bundle.subkeys[0], b2.subkeys[0], "subkeys[0]"
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

 
progress_hook = (obj) ->
  if obj.p?
    s = obj.p.toString()
    s = "#{s[0...3]}....#{s[(s.length-6)...]}"
  else
    s = ""
  interval = if obj.total? and obj.i? then "(#{obj.i} of #{obj.total})" else ""
  console.warn "+ #{obj.what} #{interval} #{s}"

main = (cb) ->
  esc = make_esc cb, "main"
  tsenc = new Encryptor { key : bufferify("shitty"), version : 2 }
  userid = 'maxtaco@keybase.io'
  passphrase = new Buffer "cats1122", "utf8"
  await bundle.sign {asp}, esc defer()
  await bundle.export_private_to_server {tsenc,asp}, esc defer pair
  await KeyManager.import_from_packed_keybase { raw : pair.keybase, asp }, defer b2
  console.log b2
 
  #await bundle.export_pgp_private_to_client { passphrase, asp }, esc defer msg
  #console.log util.inspect(pair, { depth : null })
  #console.log box(pair.keybase).toString('base64')
  #console.log msg
  #await bundle.merge_pgp_private { raw : msg, asp }, esc defer b2
  #await bundle.open_pgp { passphrase }, esc defer()
  #await bundle.open_keybase { tsenc, asp}, esc defer()
  #console.log bundle.keybase.primary
  cb null


