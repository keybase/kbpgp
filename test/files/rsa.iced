
{RSA} = require '../../lib/rsa'
{MediumRandomFountain,random_zn} = require '../../lib/primegen'

rf = new MediumRandomFountain()

run_test = (T,nbits,n,cb) ->
  await setTimeout defer(), 10
  await RSA.generate { nbits }, defer err, key 
  T.assert not(err?), "Generating keypair worked"
  await setTimeout defer(), 10
  T.waypoint "generated #{nbits} bit key!"
  for i in [0...n]
    x = random_zn rf, key.pub.n
    y = key.encrypt x
    await setTimeout defer(), 2
    z = key.decrypt y
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
