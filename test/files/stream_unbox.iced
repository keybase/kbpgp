
main = require '../../'
{util,stream} = main
{SlowFaucet,Drain} = require 'iced-stream'

#===================================================================

med = Buffer.concat ((new Buffer [0...i]) for i in [0...255])
small = Buffer.concat ((new Buffer [0...i]) for i in [0...11])

#===================================================================

oneshot = (faucet_args, xform, cb) ->
  f = new SlowFaucet faucet_args
  d = new Drain()
  f.pipe(xform)
  xform.pipe(d)
  d.once 'finish', () ->
    cb null, d.data()
  d.once 'err', (err) ->
    cb err, null

#===================================================================

R = (T, input, box_args, unbox_args, faucet_args, cb) ->
  await stream.box box_args, defer err, xform
  T.no_error err
  await oneshot { buf : input}, xform, defer err, pgp
  T.no_error err
  await stream.unbox unbox_args, defer err, xform
  faucet_args.buf = pgp
  await oneshot faucet_args, xform, defer err, output
  T.assert util.bufeq_fast(input, output), "input != output after literal roundtrip"
  console.log input.length
  console.log output.length
  cb()

#===================================================================

module.exports =
 binary_literal : (T,cb)            -> R(T, med, {}, {}, {}, cb)
 base64_literal : (T,cb)            -> R(T, med, { opts : { armor: 'generic' }}, {}, {}, cb)
 slow_binary_literal : (T,cb)       -> R(T, med, {}, {}, {blocksize : 137, wait_msec : 1}, cb)
 slow_base64_literal : (T,cb)       -> R(T, med, { opts : { armor : 'generic' } }, {}, {blocksize : 137, wait_msec : 1}, cb)
 small_slow_binary_literal : (T,cb) -> R(T, small, {}, {}, {blocksize : 3, wait_msec : 1}, cb)
 small_slow_base64_literal : (T,cb) -> R(T, small, { opts : { armor : 'generic' } }, {}, {blocksize : 3, wait_msec : 1}, cb)
 binary_compressed : (T,cb)         -> R(T, med, { opts : { compression : 'zlib' }}, {}, {}, cb)
 base64_compressed : (T,cb)         -> R(T, med, { opts : { armor: 'generic', compression : 'zlib' }}, {}, {}, cb)
 slow_binary_compressed : (T,cb)    -> R(T, med, { opts : { compression : 'zlib' }}, {}, {}, cb)
 slow_base64_compressed : (T,cb)    -> R(T, med, { opts : { armor: 'generic', compression : 'zlib' }}, {}, {blocksize:137, wait_msec :1}, cb)
