
{nbs,miller_rabin} = require '../../src/prime'
numbers = require '../data/numbers'

exports.test_primes = (T,cb) ->
  for p in numbers.primes
    T.assert miller_rabin(nbs(p), 32), "Prime #{p}"
  cb()

exports.test_composites = (T,cb) ->
  P = numbers.primes
  for p,i in P[0...(P.length - 1)]
    c = nbs(p).multiply(nbs(P[i+1]))
    T.assert not(miller_rabin(c,32)), "Composite #{c.toString()}"
  for c in numbers.carmichaels
    bn = nbs(c)
    T.assert not(miller_rabin(bn,32)), "Composite #{bn}"
  cb()
