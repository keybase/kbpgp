
{generate_rsa_keypair} = require '../../lib/rsa'
{MediumRandomFountain,random_zn} = require '../../lib/primegen'

rf = new MediumRandomFountain()

run_test = (T,nbits,n,cb) ->
  await generate_rsa_keypair { nbits }, defer key 
  await setTimeout defer(), 10
  T.waypoint "generated #{nbits} bit key!"
  for i in [0...n]
    x = random_zn rf, key.n
    y = x.modPow key.ee, key.n
    z = y.modPow key.d, key.n
    await setTimeout defer(), 10
    cmp = x.compareTo z
    T.equal cmp, 0, "Encrypt #{x.toString()}"
  cb()

exports.run_test_512 = (T, cb) ->
  await run_test T, 512, 20, defer()
  cb()

exports.run_test_1024 = (T, cb) ->
  await run_test T, 1024, 10, defer()
  cb()

exports.run_test_2048 = (T, cb) ->
  await run_test T, 2048, 5, defer()
  cb()

exports.run_test_3072 = (T, cb) ->
  await run_test T, 3072, 3, defer()
  cb()
