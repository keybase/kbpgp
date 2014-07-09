
{RSA} = require '../../lib/rsa'
{MRF} = require '../../lib/rand'

run_test = (T,nbits,n,cb) ->
  await setTimeout defer(), 10
  await RSA.generate { nbits }, defer err, key 
  T.assert not(err?), "Generating keypair worked"
  await setTimeout defer(), 10
  T.waypoint "generated #{nbits} bit key!"
  T.equal key.nbits(), nbits, "the right number of bits"
  for i in [0...n]
    x = MRF().random_zn key.pub.n
    await key.encrypt x, defer y
    await setTimeout defer(), 2
    await key.decrypt y, defer err, z
    T.no_error err
    T.waypoint "did encrypt/decrypt ##{i}"
    await setTimeout defer(), 10
    cmp = x.compareTo z
    T.equal cmp, 0, "Encrypt #{x.toString()}"
  cb()

exports.run_test_512 = (T, cb) ->
  await run_test T, 512, 10, defer()
  cb()

exports.run_test_1024 = (T, cb) ->
  await run_test T, 1024, 10, defer()
  cb()

exports.run_test_2048 = (T, cb) ->
  await run_test T, 2048, 8, defer()
  cb()

exports.run_test_3072 = (T, cb) ->
  await run_test T, 3072, 6, defer()
  cb()

exports.run_test_4096 = (T, cb) ->
  await run_test T, 4096, 5, defer()
  cb()
