{generate_keypair} = require '../../lib/keygen'
{Packet} = require '../../lib/kbpacket/base'
{bdecode} = require '../../lib/kbpacket/encode'

exports.gen1 = (T,cb) ->
  userid = new Buffer 'Rerl'
  passphrase = new Buffer 'revolt4life!'
  nbits = 1024
  await generate_keypair { nbits, userid, passphrase }, defer err, res
  T.assert not(err?), err
  buf = res.keybase.private
  T.waypoint "generated #{nbits} RSA key, and secured w/ passphrase: #{buf.toString('hex')[0...64]}..."
  [err, [tag, body ]] = bdecode buf
  T.assert not(err?), err
  T.waypoint "packet decoded"
  [err, packet] = Packet.alloc tag, body
  T.assert not(err?), err
  T.waypoint "packet allocated (tag=#{tag})"
  await packet.open { passphrase }, defer err
  T.assert not(err?), err
  T.waypoint "packet opened"
  cb()
