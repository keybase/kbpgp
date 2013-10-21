{BigInteger} = require('openpgp').bigint
{prng} = require 'triplesec'
native_rng = prng.native_rng
{Lock} = require './lock'

#==================================================

# Medium-strength fountain of random values for things like M-R  witnesses.
class MediumRandomFountain

  constructor : ->

  #---------

  nextBytes : (v) ->
    b = native_rng v.length
    v[i] = c for c,i in b

  #---------

  random_word : () -> native_rng(4).readUInt32BE 0

  #---------

  # @param {MS_RandomFountain} rf A RandomFountain
  # @param {BigInteger} n the modulus
  random_zn : (n) ->
    loop
      i = new BigInteger n.bitLength(), @
      return i if i.compareTo(BigInteger.ONE) > 0 and i.compareTo(n) < 0

#==================================================

class StrongRandomFountain 

  constructor : ->
    @buf = null
    @lock = new Lock()

  #---------

  random_word : (cb) ->
    await prng.generate 4, defer wa
    cb wa.to_buffer().readUInt32BE(0)

  #---------

  random_zn : (n, cb) ->
    go = true
    ret = false
    while go
      await @random_nbit_bigint n.bitLength(), defer ret
      go = ((ret.compareTo(BigInteger.ONE) <= 0) or (ret.compareTo(n) >= 0))
    cb i

  #---------

  nextBytes : (v) ->
    for i in [0...v.length]
      v[i] = @buf[i]

  #---------

  random_nbit_bigint : (nbits, cb) ->
    await @lock.acquire defer()
    nbytes = (nbits >> 3) + 1
    await prng.generate nbytes, defer tmp
    @buf = tmp.to_buffer()
    ret = new BigInteger nbits, @
    @lock.release()
    cb ret

#=================================================================

exports.fermat2_test = fermat2_test
exports.nbs = nbs
exports.small_primes = small_primes
exports.miller_rabin = miller_rabin
exports.random_prime = random_prime
exports.random_zn = random_zn
exports.MediumRandomFountain = MediumRandomFountain
exports.StrongRandomFountain = StrongRandomFountain

#=================================================================

