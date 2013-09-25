
{random_prime,nbs} = require './primegen'
{RSA} = require('openpgp').ciphers.asymmetric
{Montgomery,nbv,nbi,BigInteger} = require('openpgp').bigint

#=================================================================

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

#=======================================================================

generate_rsa_keypair = ({nbits, iters, e, progress_hook}, cb) ->
  e or= ((1 << 16) + 1)
  e_orig = e
  nbits or= 1024
  iters or= 10
  e = nbv e_orig

  sub_hook = (section) -> (obj) ->
    obj.section = section
    progress_hook? obj

  go = true
  while go
    nbits >>= 1 # since we have 2 primes...
    await random_prime { progress_hook : sub_hook("p"), e, nbits, iters }, defer p
    await random_prime { progress_hook : sub_hook("q"), e, nbits, iters }, defer q
    [p,q] = [q,p] if p.compareTo(q) <= 0

    q1 = q.subtract BigInteger.ONE
    p1 = p.subtract BigInteger.ONE
    phi = p1.multiply q1
    if phi.gcd(e).compareTo(BigInteger.ONE) isnt 0
      progress_hook? { what : "unlucky_phi" }
      go = true
    else
      go = false

  key = new (new RSA).keyObject()
  key.n = p.multiply(q)
  key.p = p
  key.q = q
  key.d = d = e.modInverse phi
  key.dmp1 = d.mod p1
  key.dmq1 = d.mod q1
  key.u = p.modInverse q
  key.e = e_orig
  key.ee = e

  cb key

#=======================================================================

exports.generate_rsa_keypair = generate_rsa_keypair

#=======================================================================

bench = () ->
  progress_hook = (obj) ->
    if obj.p?
      s = obj.p.toString()
      s = "#{s[0...3]}....#{s[(s.length-6)...]}"
    else
      s = ""
    interval = if obj.total? and obj.i? then "(#{obj.i} of #{obj.total})" else ""
    #console.log "+ #{obj.what} #{interval} #{s}"

  avg = new Avg()
  for i in [0...10]
    avg.start()
    await generate_rsa_keypair { nbits : 4096, progress_hook, iters: 10 }, defer key
    avg.stop()
  console.log "stats: #{avg.avg()}"
  process.exit 0

bench()

#=======================================================================
