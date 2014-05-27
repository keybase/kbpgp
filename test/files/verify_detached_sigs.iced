{PgpKeyRing} = require '../../lib/keyring'
{KeyManager} = require '../../lib/keymanager'
{do_message} = require '../../lib/openpgp/processor'
{keys,data}  = require '../data/detached'
{WordArray}  = require 'triplesec'

#=================================================

ring = new PgpKeyRing()

#==========================================

exports.init = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : keys.public }, defer err, km
  T.no_error err
  ring = new PgpKeyRing()
  ring.add_key_manager km
  cb()

#==========================================

make_data_fn = (buf) ->
  i = 0
  chunk = 0x100
  (hasher, cb) ->
    if (i < buf.length)
      end = i + chunk
      hasher WordArray.from_buffer buf[i...end]
      i = end
      done = false
    else
      done = true
    cb null, done

#==========================================

verify_good_sig = (T, name, {data,sig}, cb) -> 
  data_fn = make_data_fn(data)
  await do_message { keyfetch : ring, armored : sig, data_fn }, defer err
  T.no_error err, "sig worked for #{name}"
  T.waypoint "Sig #{name} checked out"
  cb()

#==========================================

exports.verify_good_sigs = (T,cb) ->
  for key, val of data
    await verify_good_sig T, key, val, defer()
  cb()

#==========================================
