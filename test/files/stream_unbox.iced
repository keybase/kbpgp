
main = require '../../'
{stream} = main
{Faucet,Drain} = require 'iced-stream'

#===================================================================

input = Buffer.concat ((new Buffer[0...i]) for i in [0...255])

#===================================================================

oneshot = (data, stream, cb) ->
  f = new Faucet data
  d = new Drain()
  f.pipe(stream)
  stream.pipe(d)
  d.once 'finish', () ->
    cb null, d.data()
  d.once 'err', (err) ->
    cb err, null

#===================================================================

exports.literal_roundtrip = (T,cb) ->
  await stream.box {}, defer err, xform
  await oneshot input, stream, defer err, pgp
  T.no_error err
  cb()


