
{small_primes,fermat2_test} = require '../../lib/primegen'
{nbv} = require 'bn'
{nbs} = require '../../lib/bn'
numbers = require '../data/numbers.iced'

exports.test_small_primes = (T, cb) ->
  for p in small_primes[1...]
    T.assert fermat2_test(nbv(p)), "Prime #{p}"
  cb()

exports.test_small_composites = (T,cb) ->
  for p in small_primes[1...]
    T.assert not(fermat2_test(nbv(p).add(nbv(3)))), "Composite #{p} + 3"
  cb()

exports.test_carmichael_numbers = (T,cb) ->
  C = numbers.carmichaels
  for c in C
    T.assert fermat2_test(nbs(c)), "Carmichael # #{c}"
  cb()

exports.test_larger_primes = (T,cb) ->
  P = numbers.primes
  for p in P
    T.assert fermat2_test(nbs(p)), "Prime #{p}"
  cb()

exports.test_larger_composites = (T,cb) ->
  P = numbers.primes
  for p,i in P[0...(P.length-1)]
    c = nbs(p).multiply nbs(P[i+1])
    T.assert not(fermat2_test(c)), "Composite #{c.toString()}"
  cb()

