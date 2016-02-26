{BigInteger} = require 'bn'
{WordArray,prng} = require 'triplesec'
native_rng = prng.native_rng
{Lock} = require 'iced-lock'

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
      i = BigInteger.random_nbit n.bitLength(), @
      return i if i.compareTo(BigInteger.ONE) > 0 and i.compareTo(n) < 0

#==================================================

_mrf = null
MRF = () ->
  _mrf = new MediumRandomFountain() unless _mrf?
  _mrf

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

  random_double : (cb) ->
    await prng.generate 8, defer wa
    cb wa.to_buffer().readDoubleBE(0)

  #---------

  rand_0_1 : (cb) ->
    await @random_word defer w1
    await @random_word defer w2
    ret = w1*Math.pow(2,-32) + w2*Math.pow(2,-64)
    cb ret

  #---------

  random_zn : (n, cb) ->
    go = true
    ret = false
    while go
      await @random_nbit n.bitLength(), defer ret
      go = ((ret.compareTo(BigInteger.ONE) <= 0) or (ret.compareTo(n) >= 0))
    cb ret

  #---------

  nextBytes : (v) ->
    for i in [0...v.length]
      v[i] = @buf[i]

  #---------

  # See issue https://github.com/keybase/kbpgp/issues/37
  random_word_array : (nbytes, cb) ->
    ret = new WordArray()
    max_pull = 512 # see issue above
    await @lock.acquire defer()
    while (d = (nbytes - ret.sigBytes)) > 0
      n = Math.min(max_pull, d)
      await prng.generate n, defer b
      ret = ret.concat b
    @lock.release()
    cb ret

  #---------

  random_bytes : (nbytes, cb) ->
    await @random_word_array nbytes, defer tmp
    cb tmp.to_buffer()

  #---------

  random_nbit : (nbits, cb) ->
    nbytes = (nbits >> 3) + 1
    await @random_bytes nbytes, defer tmp
    await @lock.acquire defer()
    @buf = tmp
    ret = BigInteger.random_nbit nbits, @
    @lock.release()
    cb ret

#=================================================================

_srf = null
SRF = () ->
  _srf = new StrongRandomFountain() unless _srf?
  _srf

#=================================================================

exports.MRF = MRF
exports.SRF = SRF

#=================================================================
