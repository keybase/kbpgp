{PgpKeyRing} = require '../../lib/keyring'
{KeyManager} = require '../../lib/keymanager'
{do_message} = require '../../lib/openpgp/processor'
{keys,data}  = require '../data/detached'
{WordArray}  = require 'triplesec'
{MRF}        = require '../../lib/rand'

#=================================================

ring = new PgpKeyRing()

#==========================================

random = (hi) -> MRF().random_word() % hi

#==========================================

corrupt = (inbuf, cb) ->
  outbuf = new Buffer inbuf
  i = random inbuf.length
  c = (random 0xff) + 1
  outbuf.writeUInt8((inbuf.readUInt8(i) ^ c), i)
  cb outbuf

#==========================================

exports.init = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.public }, defer err, km
  T.no_error err
  ring = new PgpKeyRing()
  ring.add_key_manager km

  # Base-64-decode the file data
  for key,val of data
    val.data = new Buffer val.data, 'base64'
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
  await do_message { keyfetch : ring, armored : sig, data }, defer err
  T.no_error err, "sig worked for #{name}"
  T.waypoint "Sig #{name} / good checked out"
  cb()

#==========================================

bad_check_sig_all_at_once = (T, name, {sig,bad_data}, cb) -> 
  await do_message { keyfetch : ring, armored : sig, data : bad_data }, defer err
  T.assert err?, "errored out on bad signature"
  T.waypoint "Sig #{name} / bad checked out"
  cb()

#==========================================

verify_good_sig_streaming = (T, name, {data,sig}, cb) -> 
  data_fn = make_data_fn(data)
  await do_message { keyfetch : ring, armored : sig, data_fn }, defer err
  T.no_error err, "sig worked for #{name}"
  T.waypoint "Sig #{name} checked out"
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
    await verify_good_sig_streaming T, key, val, defer()
  cb()

#==========================================
