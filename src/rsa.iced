{random_prime,nbs} = require './primegen'
{RSA} = require('openpgp').ciphers.asymmetric
{nbv,nbi,BigInteger} = require 'bn'
{bufeq_secure,ASP} = require './util'
{make_esc} = require 'iced-error'
C = require('./const').openpgp
K = require('./const').kb
bn = require './bn'
{SHA512} = require './hash'
{emsa_pkcs1_decode,emsa_pkcs1_encode} = require './pad'
{SRF,MRF} = require './rand'

#=======================================================================

class Priv
  constructor : ({@p,@q,@d,@dmp1,@dmq1,@u,@pub}) ->

  #--------------------

  decrypt : (c,cb) -> @mod_pow_d_crt c, cb
  sign    : (m,cb) -> @mod_pow_d_crt m, cb

  #--------------------

  serialize : () -> 
    Buffer.concat [
      @d.to_mpi_buffer()
      @p.to_mpi_buffer()
      @q.to_mpi_buffer()
      @u.to_mpi_buffer()
    ]

  #--------------------

  n : () -> @p.multiply(@q)
  phi : () -> @p.subtract(BigInteger.ONE).multiply(@q.subtract(BigInteger.ONE))
  lambda : () -> @phi.divide(@p.subtract(BigInteger.ONE).gcd(@q.subtract(BigInteger.ONE)))

  #--------------------

  @alloc : (raw, pub) ->
    orig_len = raw.length
    err = null
    mpis = []
    for i in [0...4] when not err?
      [err, mpis[i], raw] = bn.mpi_from_buffer raw
    if err then [ err, null ]
    else 
      [d,p,q,u] = mpis
      [ null, new Priv({p,d,q,u,pub}) , (orig_len - raw.length) ]

  #--------------------

  # Use Chinese remainder theorem to compute (x^d mod n) quickly.
  mod_pow_d_crt : (x,cb) ->

    # pre-compute dP, dQ
    @dP = @d.mod(@p.subtract(BigInteger.ONE)) unless @dP?
    @dQ = @d.mod(@q.subtract(BigInteger.ONE)) unless @dQ?

    # pre-compute qInv if necessary
    @qInv = @q.modInverse(@p) unless @qInv?

    ### Chinese remainder theorem (CRT) states:

      Suppose n1, n2, ..., nk are positive integers which are pairwise
      coprime (n1 and n2 have no common factors other than 1). For any
      integers x1, x2, ..., xk there exists an integer x solving the
      system of simultaneous congruences (where ~= means modularly
      congruent so a ~= b mod n means a mod n = b mod n):

      x ~= x1 mod n1
      x ~= x2 mod n2
      ...
      x ~= xk mod nk

      This system of congruences has a single simultaneous solution x
      between 0 and n - 1. Furthermore, each xk solution and x itself
      is congruent modulo the product n = n1*n2*...*nk.
      So x1 mod n = x2 mod n = xk mod n = x mod n.

      The single simultaneous solution x can be solved with the following
      equation:

      x = sum(xi*ri*si) mod n where ri = n/ni and si = ri^-1 mod ni.

      Where x is less than n, xi = x mod ni.

      For RSA we are only concerned with k = 2. The modulus n = pq, where
      p and q are coprime. The RSA decryption algorithm is:

      y = x^d mod n

      Given the above:

      x1 = x^d mod p
      r1 = n/p = q
      s1 = q^-1 mod p
      x2 = x^d mod q
      r2 = n/q = p
      s2 = p^-1 mod q

      So y = (x1r1s1 + x2r2s2) mod n
           = ((x^d mod p)q(q^-1 mod p) + (x^d mod q)p(p^-1 mod q)) mod n

      According to Fermat's Little Theorem, if the modulus P is prime,
      for any integer A not evenly divisible by P, A^(P-1) ~= 1 mod P.
      Since A is not divisible by P it follows that if:
      N ~= M mod (P - 1), then A^N mod P = A^M mod P. Therefore:

      A^N mod P = A^(M mod (P - 1)) mod P. (The latter takes less effort
      to calculate). In order to calculate x^d mod p more quickly the
      exponent d mod (p - 1) is stored in the RSA private key (the same
      is done for x^d mod q). These values are referred to as dP and dQ
      respectively. Therefore we now have:

      y = ((x^dP mod p)q(q^-1 mod p) + (x^dQ mod q)p(p^-1 mod q)) mod n

      Since we'll be reducing x^dP by modulo p (same for q) we can also
      reduce x by p (and q respectively) before hand. Therefore, let

      xp = ((x mod p)^dP mod p), and
      xq = ((x mod q)^dQ mod q), yielding:

      y = (xp*q*(q^-1 mod p) + xq*p*(p^-1 mod q)) mod n

      This can be further reduced to a simple algorithm that only
      requires 1 inverse (the q inverse is used) to be used and stored.
      The algorithm is called Garner's algorithm. If qInv is the
      inverse of q, we simply calculate:

      y = (qInv*(xp - xq) mod p) * q + xq

      However, there are two further complications. First, we need to
      ensure that xp > xq to prevent signed BigIntegers from being used
      so we add p until this is true (since we will be mod'ing with
      p anyway). Then, there is a known timing attack on algorithms
      using the CRT. To mitigate this risk, "cryptographic blinding"
      should be used (*Not yet implemented*). This requires simply
      generating a random number r between 0 and n-1 and its inverse
      and multiplying x by r^e before calculating y and then multiplying
      y by r^-1 afterwards.
    ###

    # Cryptographic blinding: compute random r,
    # r_e <- r^e mod n
    # and x <- x*r_e mod n
    #console.log "d-->"
    #console.log d.toString(16)
    #console.log @d.toString(16)
    #n = @pub.n
    #await SRF().random_zn n, defer r
    #r_e = r.modPow(@pub.e,n)             # Also do this with CRT?
    #x = x.multiply(r_e).mod(n)

    # calculate xp and xq
    xp = x.mod(@p).modPow(@dP, @p)
    xq = x.mod(@q).modPow(@dQ, @q)

    # xp must be larger than xq to avoid signed bit usage
    while xp.compareTo(xq) < 0
      xp = xp.add @p

    # do last step
    y_0 = xp.subtract(xq).multiply(@qInv).mod(@p).multiply(@q).add(xq)
    #console.log y_0.toString(16)
    #console.log r.toString(16)

    # multiply by r^-1...
    #y = y_0.multiply(r.modInverse(n)).mod(@p)

    cb y_0

#=======================================================================

class Pub
  @type : C.public_key_algorithms.RSA
  type : Pub.type

  constructor : ({@n,@e}) ->
  encrypt : (p, cb) -> @mod_pow p, @e, cb
  verify :  (s, cb) -> @mod_pow s, @e, cb

  serialize : () -> 
    Buffer.concat [
      @n.to_mpi_buffer()
      @e.to_mpi_buffer() 
    ]

  @alloc : (raw) ->
    orig_len = raw.length
    [err, n, raw] = bn.mpi_from_buffer raw
    [err, e, raw] = bn.mpi_from_buffer raw unless err?
    if err then [ err, null ]
    else [ null, new Pub({n, e}), (orig_len - raw.length) ]

  #----------------

  hash : () -> SHA512 @serialize()
  kid : () -> Buffer.concat [ @fingerprint(), new Buffer([K.kid.trailer]) ]
  fingerprint : () -> 
    Buffer.concat [
      new Buffer([K.kid.version, @type ] ),
      @hash()[0...K.kid.len]
    ]
  ekid : () -> Buffer.concat [ new Buffer([K.kid.version, @type ] ), @hash() ]

  #----------------

  mod_pow : (x,d,cb) -> cb x.modPow(d,@n)

#=======================================================================

class Pair

  @type : C.public_key_algorithms.RSA
  type : Pair.type

  #----------------

  constructor : ({@priv, @pub}) ->
    @pub.parent = @
    @priv.parent = @ if @priv?

  #----------------

  hash : () -> @pub.hash()
  kid : () -> @pub.kid()
  ekid : () -> @pub.ekid()
  fingerprint : () -> @pub.fingerprint()
  can_sign : () -> @priv?
  can_decrypt : () -> @priv?

  #----------------

  @parse : (pub_raw) ->
    [err, key, len ] = Pub.alloc pub_raw
    key = new Pair { pub : key } if key?
    [err, key, len]

  #----------------

  add_priv : (priv_raw) ->
    [err, @priv, len] = Priv.alloc priv_raw
    [err, len]

  #----------------

  @alloc : ({pub, priv}) ->
    [err, pub  ] = Pub.alloc  pub
    [err, priv ] = Priv.alloc priv, pub if not err? and priv?
    if err? then [ err, null ]
    else [ null, new Pair { priv, pub }]

  #----------------

  sanity_check : (cb) ->
    err = if @priv.n().compareTo(@pub.n) is 0 then null else new Error "pq != n"
    unless err?
      await SRF.random_zn @pub.n, defer x0
      await @encrypt x0, defer x1
      await @decrypt x1, defer x2
      err = new Error "Decrypt/encrypt failed" unless x0.compareTo(x2) is 0
    unless err?
      await SRF.random_zn @pub.n, defer y0
      await @sign y0, defer y1
      await @sign y1, defer y2
      err = new Error "Sign/verify failed" unless y0.compareTo(y2) is 0
    cb err

  #----------------

  read_priv : (raw_priv) ->
    [err,@priv] = Priv.alloc raw_priv, @pub
    err

  #----------------

  # Parse a signature out of a packet
  #
  # @param {SlicerBuffer} slice The input slice
  # @return {BigInteger} the Signature
  # @throw {Error} an Error if there was an overrun of the packet.
  @parse_sig : (slice) -> 
    [err, ret, raw, n] = bn.mpi_from_buffer slice.peek_rest_to_buffer()
    throw err if err?
    slice.advance(n)
    ret

  #----------------

  encrypt : (p, cb) -> @pub.encrypt p, cb
  decrypt : (c, cb) -> @priv.decrypt c, cb

  #----------------

  @make : ( { p, q, e, phi, p1, q1, lambda } ) ->
    n = p.multiply(q)
    d = e.modInverse lambda
    dmp1 = d.mod p1
    dmq1 = d.mod q1
    u = p.modInverse q
    pub = new Pub { n, e }
    priv = new Priv { p, q, d, dmp1, dmq1, u, pub }
    new Pair { priv, pub }

  #----------------

  to_openpgp : () ->
    key = new (new RSA).keyObject()
    key.n = @pub.n
    key.e = @pub.e.intValue()
    key.ee = @pub.e
    key.d = @priv.d
    key.p = @priv.p
    key.q = @priv.q
    key.dmp1 = @priv.dmp1
    key.dmq1 = @priv.dmq1
    key.u = @priv.u
    key

  #----------------

  sign : (m, cb) -> @priv.sign m, cb
  verify : (s) -> @pub.verify s, cb

  #----------------

  pad_and_sign : (data, {hasher}, cb) ->
    hasher or= SHA512
    hashed_data = hasher data
    m = emsa_pkcs1_encode hashed_data, @pub.n.mpi_byte_length(), {hasher}
    await @sign m, defer sig
    cb sig.to_mpi_buffer()

  #----------------

  verify_unpad_and_check_hash : (sig, data, hasher, cb) ->
    err = null
    [err, sig] = bn.mpi_from_buffer sig if Buffer.isBuffer sig
    unless err?
      await @verify sig, defer v
      b = new Buffer v.toByteArray()
      [err, hd1] = emsa_pkcs1_decode b, hasher
      unless err?
        hd2 = hasher data
        err = new Error "hash mismatch" unless bufeq_secure hd1, hd2
    cb err

  #----------------

  @generate : ({nbits, iters, e, asp}, cb) ->
    e or= ((1 << 16) + 1)
    e_orig = e
    nbits or= 4096
    iters or= 10
    asp or= new ASP({})
    e = nbv e_orig
    esc = make_esc cb, "generate_rsa_keypair"

    go = true
    nbits >>= 1 # since we have 2 primes...

    while go

      await random_prime { asp : asp.section('p'), e, nbits, iters }, esc defer p
      await asp.progress { what : "found" , p }, esc defer()
      await random_prime { asp : asp.section('q'), e, nbits, iters }, esc defer q
      await asp.progress { what : "found" , q }, esc defer()

      [p,q] = [q,p] if p.compareTo(q) <= 0

      q1 = q.subtract BigInteger.ONE
      p1 = p.subtract BigInteger.ONE
      phi = p1.multiply q1
      lambda = phi.divide(q1.gcd(p1))
      if phi.gcd(e).compareTo(BigInteger.ONE) isnt 0
        progress_hook? { what : "unlucky_phi" }
        go = true
      else
        go = false

    key = Pair.make { p, q, e, phi, p1, q1, lambda }
    cb null, key

#=======================================================================

exports.RSA = exports.Pair = Pair

#=======================================================================
