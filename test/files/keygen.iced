
{generate_keypair} = require '../../src/keygen'

exports.gen1 = (T,cb) ->
  userid = 'Rerl'
  passphrase = 'revolt4life!'
  nbits = 1024
  await generate_keypair { nbits, userid, passphrase }, defer err, res
  T.assert not(err?)
  buf = res.keybase.private
  T.waypoint "generated #{nbits} RSA key, and secured w/ passphrase: #{buf.toString('hex')[0...64]}..."
  cb()
