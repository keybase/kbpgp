
{KeyManager} = require '../..'
{keys} = require '../data/keys.iced'

exports.read_max_key = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : keys.max }, defer err, km
  T.no_error err
  cb()
