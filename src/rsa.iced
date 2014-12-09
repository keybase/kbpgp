{naive_is_prime,random_prime} = require './primegen'
bn = require './bn'
{nbits,nbv,nbi,BigInteger} = bn
{bufeq_secure,ASP} = require './util'
{make_esc} = require 'iced-error'
konst = require './const'
C = konst.openpgp
K = konst.kb
{SHA512} = require './hash'
{eme_pkcs1_encode,eme_pkcs1_decode,emsa_pkcs1_decode,emsa_pkcs1_encode} = require './pad'
{SRF,MRF} = require './rand'
{BaseKey,BaseKeyPair} = require './basekeypair'

#=======================================================================

class Priv extends BaseKey

  constructor : ({@p,@q,@d,@dmp1,@dmq1,@u,@pub}) ->

  #--------------------

  decrypt : (c,cb) ->
    await @mod_pow_d_crt c, defer x
    cb null, x

  #--------------------

  sign    : (m,cb) -> @mod_pow_d_crt m, cb

  #--------------------

  @ORDER : [ 'd', 'p', 'q', 'u' ]
  ORDER : Priv.ORDER

  #--------------------

  n : () -> @p.multiply(@q)
  phi : () -> @p.subtract(BigInteger.ONE).multiply(@q.subtract(BigInteger.ONE))
  lambda : () -> @phi.divide(@p.subtract(BigInteger.ONE).gcd(@q.subtract(BigInteger.ONE)))

  #--------------------

  @alloc : (raw, pub) -> BaseKey.alloc Priv, raw, { pub }

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
    n = @pub.n
    await SRF().random_zn n, defer r
    r_inv = r.modInverse(n)
    r_e = r.modPow(@pub.e,n)
    x_1 = x.multiply(r_e).mod(n)

    # calculate xp and xq
    xp = x_1.mod(@p).modPow(@dP, @p)
    xq = x_1.mod(@q).modPow(@dQ, @q)

    # xp must be larger than xq to avoid signed bit usage
    while xp.compareTo(xq) < 0
      xp = xp.add @p

    # do last step
    y_0 = xp.subtract(xq).multiply(@qInv).mod(@p).multiply(@q).add(xq)

    # multiply by r^-1...
    y = y_0.multiply(r_inv).mod(n)

    cb y

#=======================================================================

class Pub extends BaseKey

  #----------------

  @type : C.public_key_algorithms.RSA
  type : Pub.type

  #----------------

  @ORDER : [ 'n', 'e' ]
  ORDER : Pub.ORDER

  #----------------

  constructor : ({@n,@e}) ->
  encrypt : (p, cb) -> @mod_pow p, @e, cb
  verify :  (s, cb) -> @mod_pow s, @e, cb
  nbits : () -> @n?.bitLength()

  #----------------

  @alloc : (raw) -> BaseKey.alloc Pub, raw

  #----------------

  mod_pow : (x,d,cb) -> cb x.modPow(d,@n)

  #----------------

  validity_check : (cb) ->
    err = if (not @n.gcd(@e).equals(BigInteger.ONE)) then new Error "gcd(n,e) != 1"
    else if (not @n.mod(nbv(2)).equals(BigInteger.ONE)) then new Error "n % 2 != 1"
    else if (@e.compareTo(BigInteger.ONE) <= 0) then new Error "e <= 1"
    else if (@e.bitLength() > 32) then new Error "e=#{@e} > 2^32"
    # As of Issue #47, we've disabled this check
    #else if not naive_is_prime(@e.intValue()) then new Error "e #{@e} isn't prime!"
    else null
    cb err

#=======================================================================

class Pair extends BaseKeyPair

  @type : C.public_key_algorithms.RSA
  type : Pair.type
  get_type : () -> @type
  @klass_name : 'RSA'

  #----------------

  @Pub : Pub
  Pub : Pub
  @Priv : Priv
  Priv : Priv

  #----------------

  constructor : ({priv, pub}) ->
    super { priv, pub }

  #----------------

  @parse : (pub_raw) -> BaseKeyPair.parse Pair, pub_raw
  @alloc : ({pub, priv}) -> BaseKeyPair.alloc { pub, priv }

  #----------------

  # All subkeys use the same parent algorithm as the parent -- RSA
  @subkey_algo : (flags) -> Pair

  #----------------

  sanity_check : (cb) ->
    err = if @priv.n().compareTo(@pub.n) is 0 then null else new Error "pq != n"
    unless err?
      x0 = MRF().random_zn @pub.n
      await @encrypt x0, defer x1
      await @decrypt x1, defer err, x2
      if not err? and x0.compareTo(x2) isnt 0
        err = new Error "Decrypt/encrypt failed"
    unless err?
      y0 = MRF().random_zn @pub.n
      await @sign y0, defer y1
      await @verify y1, defer y2
      err = new Error "Sign/verify failed" unless y0.compareTo(y2) is 0
    cb err

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
  max_value : () -> @pub.n

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
  verify : (s, cb) -> @pub.verify s, cb

  #----------------

  pad_and_encrypt : (data, params, cb) ->
    err = ret = null
    await eme_pkcs1_encode data, @pub.n.mpi_byte_length(), defer err, m
    unless err?
      await @encrypt m, defer ct
      ret = @export_output { y_mpi : ct }
    cb err, ret

  #----------------

  # @param {Output} ciphertext A ciphertext in RSA::Output form
  #
  decrypt_and_unpad : (ciphertext, params, cb) ->
    err = ret = null
    await @decrypt ciphertext.y(), defer err, p
    unless err?
      b = p.to_padded_octets @pub.n
      [err, ret] = eme_pkcs1_decode b
    cb err, ret

  #----------------

  pad_and_sign : (data, {hasher}, cb) ->
    hasher or= SHA512
    hashed_data = hasher data
    m = emsa_pkcs1_encode hashed_data, @pub.n.mpi_byte_length(), {hasher}
    await @sign m, defer sig
    cb null, sig.to_mpi_buffer()

  #----------------

  verify_unpad_and_check_hash : ({sig, data, hasher, hash}, cb) ->
    err = null
    [err, sig] = bn.mpi_from_buffer sig if Buffer.isBuffer sig
    unless err?
      await @verify sig, defer v
      b = v.to_padded_octets @pub.n
      [err, hd1] = emsa_pkcs1_decode b, hasher
      unless err?
        hash or= hasher data
        err = new Error "hash mismatch" unless bufeq_secure hd1, hash
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

  #----------------

  @parse_output : (buf) -> (Output.parse buf)
  export_output : (args) -> new Output args

  #----------------

  validity_check : (cb) ->
    await @pub.validity_check defer err
    cb err

#=======================================================================

class Output

  constructor : ({@y_mpi, @y_buf}) ->

  #-------------------

  @parse : (buf) ->
    [err, ret, raw, n] = bn.mpi_from_buffer buf
    throw err if err?
    throw new Error "junk at the end of input" unless raw.length is 0
    new Output { y_mpi : ret }

  #-------------------

  y : () -> @y_mpi

  #-------------------

  hide : ({key, max, slosh}, cb) ->
    max or= 8192
    slosh or= 128
    await key.hide { i : @y(), max, slosh }, defer err, i
    unless err?
      @y_mpi = i
      @y_buf = null
    cb err

  #-------------------

  find : ({key}) -> @y_mpi = key.find @y_mpi


  #-------------------

  output : () -> (@y_buf or @y_mpi.to_mpi_buffer())

#=======================================================================

exports.RSA = exports.Pair = Pair
exports.Output = Output

#=======================================================================
