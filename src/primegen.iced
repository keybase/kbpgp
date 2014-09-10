{nbv,nbi,BigInteger} = require 'bn'
{prng} = require 'triplesec'
native_rng = prng.native_rng
{small_primes} = require './primes'
{make_esc} = require 'iced-error'
{ASP} = require './util'
{nbs} = require './bn'
{MRF,SRF} = require './rand'

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
  Bl = n.byteLength()
  for i in [bl..0]
    #t = t.modPowInt(2,n)
    t = t.square()
    if t.byteLength() > Bl
      t = t.mod(n)
    if n.testBit(i)
      t = t.shiftLeft(1)
  if t.compareTo(n) > 0
    t = t.mod(n)
  #console.log t.toString()
  ret = (t.compareTo(nbv(2)) is 0)
  #fta.stop()
  ret

#==================================================

_MR_inner = ({s, r, p, p1}) ->
  a = MRF().random_zn p
  y = a.modPow(r,p)
  if y.compareTo(BigInteger.ONE) isnt 0
    for j in [(s-1)..0] when y.compareTo(p1) isnt 0
      return false if j is 0
      y = y.square().mod(p)
      return false if y.compareTo(BigInteger.ONE) is 0
  return true

#--------------

_MR_small_check = ({p}) ->
  if p.compareTo(BigInteger.ZERO) <= 0 then false
  else if p.compareTo(nbv(7)) <= 0 then (p.intValue() in [2,3,5,7])
  else if not p.testBit(0) then false
  else true

#--------------

# Miller-Rabin primality test, with medium-strength RNGs
#
# @param {BigInteger} n The number to test
# @param {number} iter Get 1 - 4^{-iter} satisfaction
# @param {ASP} asp An ASync Package
# @param {callback} cb The callback to call when done, with (err,bool)
#
miller_rabin = ({p, iter, asp}, cb) ->
  asp or= new ASP({})
  iter or= 10
  esc = make_esc cb, "miller_rabin"

  ret = _MR_small_check { p }

  if ret
    p1 = p.subtract(BigInteger.ONE)
    s = p1.getLowestSetBit()
    r = p1.shiftRight(s)

    ret = true
    for i in [0...iter]
      await asp.progress { what : "mr", i, total : iter, p }, esc defer()
      unless _MR_inner { s, r, p, p1 }
        ret = false
        break

    await asp.progress { what : "mr", i : iter, total : iter, p }, esc defer()

  cb null, ret

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
prime_search = ({start, range, sieve, asp, iters}, cb) ->
  iters or= 20
  pf = new PrimeFinder start, sieve
  pf.setmax range
  pvec = (pp while ((pp = pf.next_weak()).compareTo(BigInteger.ZERO) > 0))
  esc = make_esc cb, "prime_search"

  ret = null
  while pvec.length and not ret?
    i = MRF().random_word() % pvec.length
    p = pvec[i]

    await asp.progress { what : "fermat", p }, esc defer()
    if not fermat2_test(p) then # noop
    else
      await miller_rabin { p, iters, asp }, esc defer is_prime
      await asp.progress { what : "passed_mr", p }, esc defer()
      if is_prime then ret = p
      else asp.progress { what : "failed_mr", p }

    tmp = pvec.pop()
    pvec[i] = tmp if i < pvec.length

  ret = nbv(0) if not ret?
  cb null, ret

#=================================================================

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
random_prime = ({nbits, iters, asp, e}, cb) ->
  sieve = [1,2]
  go = true
  esc = make_esc cb, "random_prime"
  range = nbits
  p = null

  while go
    await SRF().random_nbit nbits, defer p
    p = p.setBit(0).setBit(nbits-1).setBit(nbits-2)
    if not e? or p.subtract(BigInteger.ONE).gcd(e).compareTo(BigInteger.ONE) is 0
      await asp.progress { what : "guess", p }, esc defer()
      await prime_search { start : p, range, sieve, asp, iters }, esc defer p
      go = not p? or (p.compareTo(BigInteger.ZERO) is 0)

  await asp.progress { what : "found", p }, esc defer()
  cb null, p

#=================================================================

exports.naive_is_prime = naive_is_prime = (n) ->
  biggest = Math.floor(Math.sqrt(n))
  for p in small_primes
    if p > biggest then return true
    if (n % p) is 0 then return false
  return false

#=================================================================

exports.fermat2_test = fermat2_test
exports.nbs = nbs
exports.small_primes = small_primes
exports.miller_rabin = miller_rabin
exports.random_prime = random_prime

#=================================================================
