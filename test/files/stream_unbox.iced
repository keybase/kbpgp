
main = require '../../'
{util,stream} = main
{Faucet,Drain} = require 'iced-stream'

#===================================================================

input = Buffer.concat ((new Buffer [0...i]) for i in [0...255])

#===================================================================

oneshot = (data, xform, faucet_opts, cb) ->
  f = new Faucet data, faucet_opts
  d = new Drain()
  f.pipe(xform)
  xform.pipe(d)
  d.once 'finish', () ->
    cb null, d.data()
  d.once 'err', (err) ->
    cb err, null

#===================================================================

roundtrip = (T, box_args, unbox_args, faucet_args, cb) ->
  await stream.box box_args, defer err, xform
  T.no_error err
  await oneshot input, xform, {}, defer err, pgp
  T.no_error err
  await stream.unbox unbox_args, defer err, xform
  await oneshot pgp, xform, faucet_args, defer err, output
  T.assert util.bufeq_fast(input, output), "input != output after literal roundtrip"
  cb()

#===================================================================

exports.binary_literal = (T,cb) -> roundtrip(T, {}, {}, {}, cb)
exports.base64_literal = (T,cb) -> roundtrip(T, { opts : { armor: 'generic' }}, {}, {}, cb)
