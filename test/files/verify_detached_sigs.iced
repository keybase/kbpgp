{PgpKeyRing} = require '../../lib/keyring'
{KeyManager} = require '../../'
{do_message} = require '../../lib/openpgp/processor'
{keys,data}  = require '../data/detached.iced'
{WordArray}  = require 'triplesec'
{MRF}        = require '../../lib/rand'

#=================================================

ring = new PgpKeyRing()
km = null

#==========================================

random = (hi) -> MRF().random_word() % hi
strip = (m) -> m.replace /[\n\t\r ]+/g, ''

#==========================================

corrupt = (inbuf, cb) ->
  outbuf = new Buffer inbuf
  i = random inbuf.length
  c = (random 0xff) + 1
  outbuf.writeUInt8((inbuf.readUInt8(i) ^ c), i)
  cb outbuf

#==========================================

exports.init = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.public }, defer err, tmp
  T.no_error err
  km = tmp
  ring = new PgpKeyRing()
  ring.add_key_manager km

  # Base-64-decode the file data
  for key,val of data
    val.data = new Buffer strip(val.data), 'base64'
    await corrupt val.data, defer val.bad_data

  cb()

#==========================================

make_data_fn = (buf) ->
  i = 0
  chunk = 0x1000
  (hasher, cb) ->
    if (i < buf.length)
      end = i + chunk
      hasher buf[i...end]
      i = end
      done = false
    else
      done = true
    cb null, done

#==========================================

good_check_sig_all_at_once = (T, name, {data,sig,bad_data}, cb) ->
  await do_message { keyfetch : ring, armored : sig, data }, defer err, literals
  T.no_error err, "sig worked for #{name}"
  T.waypoint "Sig #{name} / good checked out"
  T.assert literals[0].get_data_signer(), "a data signer came back"
  km2 = literals[0].get_data_signer()?.get_key_manager()
  T.assert km2?, "A key manager was there"
  fp1 = km.get_pgp_fingerprint().toString('hex')
  fp2 = literals[0].get_data_signer()?.get_key_manager()?.get_pgp_fingerprint()?.toString("hex")
  T.equal fp1, fp2, "the right fingerprint signed"
  cb()

#==========================================

bad_check_sig_all_at_once = (T, name, {sig,bad_data}, cb) ->
  await do_message { keyfetch : ring, armored : sig, data : bad_data }, defer err
  T.assert err?, "errored out on bad signature"
  T.waypoint "Sig #{name} failed"
  cb()

#==========================================

good_check_sig_streaming = (T, name, {data,sig}, cb) ->
  data_fn = make_data_fn(data)
  await do_message { keyfetch : ring, armored : sig, data_fn }, defer err, literals
  T.no_error err, "sig worked for #{name}"
  T.waypoint "Sig #{name} checked out"
  T.assert literals[0].get_data_signer(), "a data signer came back"
  km2 = literals[0].get_data_signer()?.get_key_manager()
  T.assert km2?, "A key manager was there"
  fp1 = km.get_pgp_fingerprint().toString('hex')
  fp2 = literals[0].get_data_signer()?.get_key_manager()?.get_pgp_fingerprint()?.toString("hex")
  T.equal fp1, fp2, "the right fingerprint signed"
  cb()

#==========================================

bad_check_sig_streaming = (T, name, {bad_data,sig}, cb) ->
  data_fn = make_data_fn(bad_data)
  await do_message { keyfetch : ring, armored : sig, data_fn }, defer err
  T.assert err?, "errored out on bad signature"
  T.waypoint "Sig #{name} failed"
  cb()

#==========================================
exports.verify_good_sigs_all_at_once = (T,cb) ->
  for key, val of data
    await good_check_sig_all_at_once T, key, val, defer()
  cb()

#==========================================

exports.nix_bad_sigs_all_at_once = (T,cb) ->
  for key, val of data
    await bad_check_sig_all_at_once T, key, val, defer()
  cb()

#==========================================

exports.verify_good_sigs_streaming = (T,cb) ->
  for key, val of data
    await good_check_sig_streaming T, key, val, defer()
  cb()

#==========================================

exports.nix_bad_sigs_streaming = (T,cb) ->
  for key, val of data
    await bad_check_sig_streaming T, key, val, defer()
  cb()

#==========================================
