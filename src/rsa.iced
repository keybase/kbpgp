{random_prime,nbs} = require './primegen'
{RSA} = require('openpgp').ciphers.asymmetric
{nbv,nbi,BigInteger} = require('openpgp').bigint
{bufeq_secure,ASP} = require './util'
{make_esc} = require 'iced-error'
C = require('./const').openpgp
bn = require './bn'
{SHA512} = require './hash'
{emsa_pkcs1_decode,emsa_pkcs1_encode} = require './pad'

#=======================================================================

class Priv
  constructor : ({@p,@q,@d,@dmp1,@dmq1,@u,@pub}) ->

  decrypt : (c) -> c.modPow @d, @pub.n
  sign    : (m) -> m.modPow @d, @pub.n

  serialize : () -> 
    Buffer.concat [
      @d.to_mpi_buffer()
      @p.to_mpi_buffer()
      @q.to_mpi_buffer()
      @u.to_mpi_buffer()
    ]

  n : () -> @p.multiply(@q)
  phi : () -> @p.subtract(BigInteger.ONE).multiply(@q.subtract(BigInteger.ONE))
  lambda : () -> @phi.divide(@p.subtract(BigInteger.ONE).gcd(@q.subtract(BigInteger.ONE)))

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

#=======================================================================

class Pub
  constructor : ({@n,@e}) ->
  encrypt : (p) -> p.modPow @e, @n
  verify :  (s) -> s.modPow @e, @n

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


#=======================================================================

class Pair

  @type : C.public_key_algorithms.RSA
  type : Pair.type

  constructor : ({@priv, @pub}) ->
    @pub.parent = @
    @priv.parent = @ if @priv?

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

  sanity_check : () ->
    return new Error "pq != n" unless @priv.n().compareTo(@pub.n) is 0
    test = nbs("1111777111771")
    return "Decrypt/encrypt failed" unless @decrypt(@encrypt(test)).compareTo(test) is 0
    return "Sign/verify failed" unless @verify(@sign(test)).compareTo(test) is 0
    return null

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

  encrypt : (p) -> @pub.encrypt p
  decrypt : (c) -> @priv.decrypt c

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

  sign : (m) -> @priv.sign m
  verify : (s) -> @pub.verify s

  #----------------

  pad_and_sign : (data, {hasher}) ->
    hasher or= SHA512
    hashed_data = hasher data
    m = emsa_pkcs1_encode hashed_data, @pub.n.mpi_byte_length(), {hasher}
    @sign(m).to_mpi_buffer()

  #----------------

  verify_unpad_and_check_hash : (sig, data, hasher) ->
    err = null
    [err, sig] = bn.mpi_from_buffer sig if Buffer.isBuffer sig
    unless err?
      v = @verify sig
      b = new Buffer v.toByteArray()
      [err, hd1] = emsa_pkcs1_decode b, hasher
      unless err?
        hd2 = hasher data
        err = new Error "hash mismatch" unless bufeq_secure hd1, hd2
    err

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
