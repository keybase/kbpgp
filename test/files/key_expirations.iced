
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
