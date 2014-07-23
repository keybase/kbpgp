
main = require '../../'
{util,stream} = main
{SlowFaucet,Drain} = require 'iced-stream'

#===================================================================

med = Buffer.concat ((new Buffer [0...i]) for i in [0...92])
small = Buffer.concat ((new Buffer [0...i]) for i in [0...5])

#===================================================================

oneshot = (faucet_args, xform, cb) ->
  f = new SlowFaucet faucet_args
  d = new Drain()
  f.pipe(xform)
  xform.pipe(d)
  d.once 'finish', () ->
    console.log "and we are done!"
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
  if not util.bufeq_fast(input, output)
    console.log input
    console.log output
    console.log input.length
    console.log output.length
    if output.length < input.length
      if util.bufeq_fast(input[0...output.length], output)
        console.log "tis but an error of omission"
    T.assert false , "failed equality assertion"
  cb()

#===================================================================

module.exports =
 small_binary_literal : (T,cb)       -> R(T, small, {}, {}, {}, cb)
 small_base64_literal : (T,cb)       -> R(T, small, { opts : { armor: 'generic' }}, {}, {}, cb)
 med_binary_literal : (T,cb)         -> R(T, med, {}, {}, {}, cb)
 base64_literal : (T,cb)             -> R(T, med, { opts : { armor: 'generic' }}, {}, {}, cb)
 slow_binary_literal : (T,cb)        -> R(T, med, {}, {}, {blocksize : 137, wait_msec : 1}, cb)
 slow_base64_literal : (T,cb)        -> R(T, med, { opts : { armor : 'generic' } }, {}, {blocksize : 137, wait_msec : 1}, cb)
 small_slow_binary_literal : (T,cb)  -> R(T, small, {}, {}, {blocksize : 2, wait_msec : 3}, cb)
 small_slow_base64_literal : (T,cb)  -> R(T, small, { opts : { armor : 'generic' } }, {}, {blocksize : 1, wait_msec : 4}, cb)
 binary_compressed : (T,cb)          -> R(T, med, { opts : { compression : 'zlib' }}, {}, {}, cb)
 base64_compressed : (T,cb)          -> R(T, med, { opts : { armor: 'generic', compression : 'zlib' }}, {}, {}, cb)
 slow_binary_compressed : (T,cb)    -> R(T, med, { opts : { compression : 'zlib' }}, {}, {}, cb)
 slow_base64_compressed : (T,cb)    -> R(T, med, { opts : { armor: 'generic', compression : 'zlib' }}, {}, {blocksize: 200, wait_msec :1}, cb)
