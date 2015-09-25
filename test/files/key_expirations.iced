
{KeyManager} = require '../..'
{keys} = require '../data/keys.iced'

exports.read_max_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : keys.max }, defer err, km
  T.no_error err
  ten_years = 10 * 365 * 24 * 60 * 60
  T.equal ten_years, km.primary.lifespan.expire_in, "Max's key expires in ten years"
  cb()

exports.read_jack_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : keys.jack_no_expire }, defer err, km
  T.no_error err
  T.equal null, km.primary.lifespan.expire_in, "Jack's key does not expire"
  cb()

exports.read_rillian_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : keys.rillian }, defer err, km
  T.no_error err
  T.equal 210821778, km.primary.lifespan.expire_in, "rillian's key expires in 6y250d1h36m + epsilon"
  cb()

exports.read_michel_slm_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : keys.michel_slm }, defer err, km, warnings
  T.assert err?, "key is expired"
  T.assert (err.toString().indexOf("no valid primary key self-signature") > 0), "the right error"
  w0 = warnings.warnings()[0]
  m = w0.match /Signature failure in packet 1: Key expired (\d+)s ago/
  T.assert m?, "matched warning 1"
  T.assert (m[1] > 18169267), "expiration was more than 18169267s ago"
  cb()

exports.read_kourier_key = (T,cb) ->
  opts = { time_travel : true }
  await KeyManager.import_from_armored_pgp { armored : keys.kourier, opts }, defer err, km, warnings
  T.no_error err
  T.assert not(km.primary._pgp.get_expire_time().expire_at), "key doesn't expire"
  cb()
