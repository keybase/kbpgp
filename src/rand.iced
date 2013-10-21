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

  random_zn : (n, cb) ->
    go = true
    ret = false
    while go
      await @random_nbit n.bitLength(), defer ret
      go = ((ret.compareTo(BigInteger.ONE) <= 0) or (ret.compareTo(n) >= 0))
    cb i

  #---------

  nextBytes : (v) ->
    for i in [0...v.length]
      v[i] = @buf[i]

  #---------

  random_nbit : (nbits, cb) ->
    await @lock.acquire defer()
    nbytes = (nbits >> 3) + 1
    await prng.generate nbytes, defer tmp
    @buf = tmp.to_buffer()
    ret = new BigInteger nbits, @
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
