{generate_keypair} = require '../../lib/keygen'
{Packet} = require '../../lib/keybase/packet/base'
{bdecode} = require '../../lib/keybase/encode'

exports.gen1 = (T,cb) ->
  userid = 'Rerl'
  passphrase = 'revolt4life!'
  nbits = 1024
  await generate_keypair { nbits, userid, passphrase }, defer err, res
  T.no_error err
  buf = res.keybase.private
  T.waypoint "generated #{nbits} RSA key, and secured w/ passphrase: #{buf.toString('hex')[0...64]}..."
  [err, [tag, body ]] = bdecode buf
  T.no_error err
  T.waypoint "packet decoded"
  [err, packet] = Packet.alloc tag, body
  T.no_error err
  T.waypoint "packet allocated (tag=#{tag})"
  await packet.open { passphrase }, defer err
  T.no_error err
  T.waypoint "packet opened"
  err = packet.key.sanity_check()
  T.no_error err
  T.waypoint "key sanity checked"
  cb()
