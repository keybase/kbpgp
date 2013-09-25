
{miller_rabin} = require '../../lib/primegen'
numbers = require '../data/numbers.iced'
{nbs} = require '../../lib/bn'

run_mr = (p, desired, what, T, cb) ->
  await miller_rabin { p, iter : 32 }, defer err, is_prime
  s = p.toString()
  T.assert not(err?), "#{what} #{s} had an error: #{if err? then err.toString() else ''}"
  T.assert (is_prime is desired), "#{what} #{s} primality = #{desired}"
  cb()

exports.test_primes = (T,cb) ->
  for p in numbers.primes
    await run_mr nbs(p), true, "prime", T, defer()
  cb()

exports.test_composites = (T,cb) ->
  P = numbers.primes
  for p,i in P[0...(P.length - 1)]
    c = nbs(p).multiply(nbs(P[i+1]))
    await run_mr c, false, "composite", T, defer()
  for c in numbers.carmichaels
    bn = nbs(c)
    await run_mr bn, false, "Carmichael", T, defer()
  cb()
