{Montgomery,nbv,nbi,BigInteger} = require('openpgp').bigint
{prng} = require 'triplesec'
native_rng = prng.native_rng

#=================================================================

#
# Code for generating Random Primes, ported from SFS:
#  
#  https://github.com/okws/sfslite/blob/master/crypt/random_prime.C
# 
#  Originally:  Copyright (C) 1998 David Mazieres (dm@uun.org)
#

#=================================================================

class Timer
  constructor : () -> @start = Date.now()
  stop : -> (Date.now() - @start)
class Avg
  constructor : () ->
    @tot = 0
    @n = 0
  start : () ->
    @_t = Date.now()
  stop : () -> 
    s = (Date.now() - @_t)
    console.log "ran in #{s}"
    @tot += s
    @n++
  avg : -> @tot/@n

#=================================================================

{small_primes} = require './primes'
# small_primes = small_primes[0...100]

#=================================================================

# Generate a BigInt from a string s, and a base.
# @param {String} s the BigInt
# @param {number} base the base that the string is in
# @return {BigInteger} the result
nbs = (s, base = 10) ->
  r = nbi()
  r.fromString s, base
  r
  
#=================================================================

# Compute (p % d)
# @param {BigInteger} p 
# @param {number} d
# @return {number} p%d
quickmod = (p, d) -> 
  p.modInt(d)

#--------------

# Fremat's pseudo-prime tester. Test with a=2. Test to see if 2^(n-1) mod n ?= 1,
# or equivalently, if 2^(n) mod n ?= 2.
#
# @param {BigInteger} n
# @return {Boolean} true if the check succeeds and false otherwise.
#
fta = new Avg()
fermat2_test = (n) ->
  #y = nbv(2).modPow(n.subtract(nbv(1)),n)
  #ret = (y.compareTo(BigInteger.ONE) is 0)
  #fta.start()
  #return ret
  #console.log(y.toString())
  t = nbv(1)
  bl = n.bitLength()
  bl--
  for i in [bl..0]
    t = t.modPowInt(2,n)
    #t = t.square()
    # .t in jsbn is equivalent to _mp_size in GNU bigint.  _mp_size
    # is the "number of limbs" in the bigint
    #if t.t > n.t
    #  t = t.mod(n)
    if n.testBit(i)
      t = t.shiftLeft(1)
  if t.compareTo(n) > 0
    t = t.mod(n)
  #console.log t.toString()
  ret = (t.compareTo(nbv(2)) is 0)
  #fta.stop()
  ret

#--------------

# Medium-strength random values for things like M-R
# witnesses.
ms_random_word = () ->   native_rng(4).readUInt32BE 0

# Medium-strength fountain of random values
class MS_RandomFountain
  constructor : ->
  nextBytes : (v) ->
    b = native_rng v.length
    v[i] = c for c,i in b

#--------------

# @param {MS_RandomFountain} rf A RandomFountain
# @param {BigInteger} n the modulus
ms_random_zn = (rf, n) ->
  loop
    i = new BigInteger n.bitLength(), rf
    return i if i.compareTo(BigInteger.ONE) > 0 and i.compareTo(n) < 0

#--------------

# Miller-Rabin primality test, with medium-strength RNGs
#
# @param {BigInteger} n The number to test
# @param {number} iter Get 1 - 4^{-iter} satisfaction
# @return {Boolean} T/F depending on whether it passes or not
#
miller_rabin = (n, iter, progress_hook) ->
  return false if n.compareTo(BigInteger.ZERO) <= 0
  if n.compareTo(nbv(7) <= 0)
    iv = n.intValue()
    return iv in [2,3,5,7]
  return false if not n.testBit(0)

  n1 = n.subtract(BigInteger.ONE)
  s = n1.getLowestSetBit()
  r = n1.shiftRight(s)

  msrf = new MS_RandomFountain()

  for i in [0...iter]
    progress_hook? { what : "mr", i, total : iter, p : n }
    a = ms_random_zn msrf, n
    y = a.modPow(r,n)
    if y.compareTo(BigInteger.ONE) isnt 0
      for j in [(s-1)..0] when y.compareTo(n1) isnt 0
        return false if j is 0
        y = y.square().mod(n)
        return false if y.compareTo(BigInteger.ONE) is 0

  progress_hook? { what : "mr", i : iter, total : iter, p : n }
  return true

#=================================================================

class PrimeFinder

  constructor : (@p, @sieve) ->
    @inc = 0
    @maxinc = -1
    @sievepos = quickmod @p, @sieve.length
    @calcmods()

  #-----------------------

  getp : () -> @p

  #-----------------------

  setmax : (i) -> 
    throw new Error "can only setmax() once" unless @maxinc is -1
    @maxinc = i

  #-----------------------

  calcmods : () ->
    @p = @p.add nbv @inc
    @maxinc -= @inc unless @maxinc is -1
    @inc = 0
    @mods = ( quickmod(@p, sp) for sp in small_primes)

  #-----------------------

  decrement_mods_find_divisor : () ->
    for sp,i in small_primes
      while (@mods[i] + @inc >= sp)
        @mods[i] -= sp
        if (@mods[i] + @inc) is 0
          return true 
    return false

  #-----------------------

  #
  # Return the next weak prime > @p.  Basically runs a sieve to see
  # if any of the small primes divide the next candidate, and keeps 
  # advancing until we find one that seems prime w/r/t to the small primes.
  #
  # This is crazy-optimized, but let's leave it for now...
  #
  # @return {BigInteger} the next weak prime
  #
  next_weak : () ->
    loop
      step = @sieve[@sievepos]
      @sievepos = (@sievepos + step) % @sieve.length
      @inc += step
      if @inc > @maxinc and @maxinc > 0
        @tmp = nbv(0)
        return @tmp
      @calcmods() if @inc < 0
      unless @decrement_mods_find_divisor()
        @tmp = @p.add nbv @inc
        return @tmp

  #-----------------------

  next_fermat : () ->
    loop
      @next_weak()
      return @tmp if not(@tmp) or fermat2_test(@tmp)

  #-----------------------

  next_strong : (iter = 32) ->
    loop
      @next_weak()
      return @tmp if not(@tmp) or (fermat2_test(@tmp) and probab_prime(@tmp, iter))

#=================================================================

# Find a prime starting at the given start, and going up to start+range.
# 
# Use the sieve for primality testing, which in the case of regular odd
# primes is [1,2], and for strong primes is more interesting...
#
prime_search = ({start, range, sieve, progress_hook, iters}) ->
  iters or= 20
  pf = new PrimeFinder start, sieve
  pf.setmax range
  pvec = (pp while ((pp = pf.next_weak()).compareTo(BigInteger.ZERO) > 0))

  while pvec.length
    i = ms_random_word() % pvec.length
    p = pvec[i]

    progress_hook? { what : "fermat", p }
    if not fermat2_test(p) then # noop
    else if miller_rabin(p, iters, progress_hook)
      progress_hook? { what : "passed_mr", p }
      return p
    else
      progress_hook? { what : "failed_mr", p }

    tmp = pvec.pop()
    pvec[i] = tmp if i < pvec.length

  return nbv(0)

#=================================================================

#-----------------------

class StrongRandomFountain 
  constructor : ->
    @buf = null
  recharge : (cb) ->
    await prng.generate Math.floor(7000/8), defer tmp
    @buf = tmp.to_buffer()
    cb()
  nextBytes : (v) ->
    throw new Error "need a recharge!" unless @buf?
    for i in [0...v.length]
      v[i] = @buf[i]
    @buf = null

#-----------------------

#
# Find a random prime that is nbits long, with certainty
# 1 - 2^{-iter}
#
# @param {number} nbits The number of bits in the prime
# @param {number} iters The number of time to run Miller-Rabin
# @param {callback} Callback with the {BigInteger} result
# @param {function} progress_hook A hook to call to update progress
# @param {BigInteger} e The generated prime must p must have gcd(p-1,e) = 1
#   if specified. If not, this check isn't performed. This is useful for RSA.
#   It saves a tiny bit of work, but not much if e = 2^16+1 as usual.
#
random_prime = ({nbits, iters, progress_hook, e}, cb) ->
  srf = new StrongRandomFountain()
  sieve = [1,2]
  go = true
  i = 0
  while go 
    await srf.recharge defer()
    p = new BigInteger nbits, srf
    p = p.setBit(0).setBit(nbits-1)
    if not e? or p.subtract(BigInteger.ONE).gcd(e).compareTo(BigInteger.ONE) is 0
      progress_hook? { what : "guess", p }
      p = prime_search { start : p, range : nbits/4, sieve, progress_hook, iters }
      go = (p.compareTo(BigInteger.ZERO) is 0)
  progress_hook? { what : "found", p }
  cb p

#=================================================================

exports.fermat2_test = fermat2_test
exports.nbs = nbs
exports.small_primes = small_primes
exports.miller_rabin = miller_rabin
exports.random_prime = random_prime

#=================================================================

progress_hook = (obj) ->
  s = obj.p.toString()
  interval = if obj.total? and obj.i? then "(#{obj.i} of #{obj.total})" else ""
  console.log "+ #{obj.what} #{interval} #{s[0...3]}....#{s[(s.length-6)...]}"
await random_prime { nbits : 1024, iters : 10, progress_hook, e : nbv((1 << 16) + 1) }, defer p
console.log p.toString()
process.exit -1

