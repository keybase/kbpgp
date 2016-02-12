
C = require('../../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
RSA = require('../../rsa').Pair
DSA = require('../../dsa').Pair
ElGamal = require('../../elgamal').Pair
ElGamalSE = require('../../elgamalse').Pair
ECDSA = require('../../ecc/ecdsa').Pair
ECDH = require('../../ecc/ecdh').Pair
EDDSA = require('../../ecc/eddsa').Pair
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{calc_checksum} = require '../util'
{bufferify,unix_time,bufeq_secure,katch,make_time_packet,uint_to_buffer} = require '../../util'
{decrypt,encrypt} = require '../cfb'
{Packet} = require './base'
S = require './signature'
{Signature} = S
{encode} = require '../armor'
{S2K,SecretKeyMaterial} = require '../s2k'
symmetric = require '../../symmetric'
util = require 'util'
packetsigs = require './packetsigs'

#=================================================================================

class KeyMaterial extends Packet

  #
  # @param {Pair} key a Keypair that can be used for signing, etc.
  # @param {number} timestamp Uint32 saying what time the key was born
  # @param {string|Buffer} passphrase The passphrase used to lock the key
  # @param {SecretKeyMaterial} skm A wrapper around the {S2K} object;
  #                  the encryption engine used to lock the secret parts of the key
  # @param {Object} opts a list of options
  # @param {number} flags The flags to grant this key
  # @option opts {bool} subkey True if this is a subkey
  constructor : ({@key, @timestamp, @passphrase, @skm, @opts, @flags}) ->
    @opts or= {}
    @flags or= 0
    @_is_duplicate_primary = false
    super()

  #--------------------------

  _write_private_enc : (bufs, priv, pp) ->
    bufs.push new Buffer [
      C.s2k_convention.sha1,                  # Indicates s2k with SHA1 checksum
      C.symmetric_key_algorithms.AES256,      # Sym algo used to encrypt
      C.s2k.salt_iter,                        # s2k salt+iterative
      C.hash_algorithms.SHA256                # s2k hash algo
    ]
    sha1hash = (new SHA1).bufhash priv        # checksum of the cleartext MPIs
    salt = native_rng 8                       # 8 bytes of salt
    bufs.push salt
    c = 96
    bufs.push new Buffer [ c ]                # ??? translates to a count of 65336 ???
    ks = AES.keySize
    k = (new S2K).write pp, salt, c, ks       # expanded encryption key (via s2k)
    ivlen = AES.blockSize                     # ivsize = msgsize
    iv = native_rng ivlen                     # Consider a truly random number in the future
    bufs.push iv                              # push the IV on before the ciphertext

    # horrible --- 'MAC' then encrypt :(
    plaintext = Buffer.concat [ priv, sha1hash ]

    # Encrypt with CFB/mode + AES.  Use the expanded key from s2k
    ct = encrypt { block_cipher_class : AES, key : k, plaintext, iv }

    bufs.push ct

  #--------------------------

  _write_private_clear : (bufs, priv) ->
    bufs.push(
      new Buffer([C.s2k_convention.none]),
      priv,
      uint_to_buffer(16, calc_checksum(priv))
    )

  #--------------------------

  _write_public : (bufs) ->
    pub = @key.serialize()
    bufs.push(
      new Buffer([ C.versions.keymaterial.V4 ]),   # Since PGP 5.x, this is prefered version
      uint_to_buffer(32, @timestamp),
      new Buffer([ @key.type ]),
      pub
    )

  #--------------------------

  _write_dummy : (bufs) ->
    bufs.push(
      new Buffer([
        C.s2k_convention.sha1               # dummy, pro-forma
        C.symmetric_key_algorithms.AES256   # dummy, pro-forma
        C.s2k.gnu                           # The GNU s2k param
        0x2                                 # Not sure, maybe a version #?
      ]),
      new Buffer("GNU", "utf8"),            # The "GNU" ascii art goes next
      new Buffer([ 0x1 ])                   # Finally, 0x1 means "dummy"
    )

  #--------------------------

  add_flags : (v) -> @flags |= v

  #--------------------------

  private_body : (opts) ->
    bufs = []
    @_write_public bufs
    priv = if (p = @key.priv)? then p.serialize() else null
    pp = opts.passphrase or @passphrase

    if not priv? then @_write_dummy         bufs
    else if pp?  then @_write_private_enc   bufs, priv, pp
    else              @_write_private_clear bufs, priv

    ret = Buffer.concat bufs
    ret

  #--------------------------

  private_framed : (opts) ->
    body = @private_body opts
    T = C.packet_tags
    tag = if opts.subkey then T.secret_subkey else T.secret_key
    @frame_packet tag, body

  #--------------------------

  public_body : () ->
    bufs = []
    @_write_public bufs
    Buffer.concat bufs

  #--------------------------

  get_fingerprint : () ->
    data = @public_body()
    (new SHA1).bufhash Buffer.concat [
      new Buffer([ C.signatures.key ]),
      uint_to_buffer(16, data.length),
      data
    ]

  #--------------------------

  get_key_id : () -> @get_fingerprint()[12...20]
  get_short_key_id : () -> @get_key_id()[-4...].toString('hex').toUpperCase()

  #--------------------------

  get_klass : () -> @key.constructor

  #--------------------------

  export_framed : (opts = {}) ->
    if opts.private then @private_framed opts
    else @public_framed opts

  #--------------------------

  public_framed : (opts = {}) ->
    body = @public_body()
    T = C.packet_tags
    tag = if opts.subkey then T.public_subkey else T.public_key
    @frame_packet tag, body

  #--------------------------

  to_signature_payload : () ->
    pk = @public_body()

    # RFC 4880 5.2.4 Computing Signatures Over a Key
    Buffer.concat [
      new Buffer([ C.signatures.key ] ),
      uint_to_buffer(16, pk.length),
      pk
    ]

  #--------------------------

  self_sign_key : ({userids, lifespan, raw_payload}, cb) ->
    err = null
    sigs = []
    primary = true
    for userid in userids when not err?
      sig = null
      if @key.can_sign() or raw_payload
        await @_self_sign_key { userid, lifespan, raw_payload, primary }, defer err, sig
      else if not (sig = userid.get_framed_signature_output())?
        err = new Error "Cannot sign key --- don't have a private key, and can't replay"
      primary = false
      sigs.push sig
    cb err, sig

  #--------------------------

  _self_sign_key : ( {userid, lifespan, raw_payload, primary}, cb) ->
    payload = Buffer.concat [ @to_signature_payload(), userid.to_signature_payload() ]

    # XXX Todo -- Implement Preferred Compression Algorithm --- See Issue #16
    type = C.sig_types.positive

    hsp = [
      new S.CreationTime(lifespan.generated)
      new S.KeyFlags([@flags])
      new S.PreferredSymmetricAlgorithms([C.symmetric_key_algorithms.AES256, C.symmetric_key_algorithms.AES128])
      new S.PreferredHashAlgorithms([C.hash_algorithms.SHA512, C.hash_algorithms.SHA256])
      new S.Features([C.features.modification_detection])
      new S.KeyServerPreferences([C.key_server_preferences.no_modify])
      new S.PreferredCompressionAlgorithms([C.compression.zlib, C.compression.zip])
    ]
    if primary
      hsp.push new S.PrimaryUserId(1)

    if lifespan.expire_in
      hsp.push new S.KeyExpirationTime(lifespan.expire_in)

    sig = new Signature {
      type : type,
      key : @key,
      hashed_subpackets : hsp,
      unhashed_subpackets : [ new S.Issuer(@get_key_id()) ]
    }

    # raw_payload is when we want to just output what would have been signed without actually
    # signing it.  We need this for patching keys in the client.
    if raw_payload
      sig = payload
    else
      # We just store the output in the signature object itself
      await sig.write payload, defer err

      ps = new packetsigs.SelfSig { userid, type, sig, options : @flags }
      userid.push_sig ps
      @push_sig ps

    cb err, sig

  #--------------------------

  sign_subkey : ({subkey, lifespan}, cb) ->
    err = sig = null
    if @key.can_sign()
      await @_sign_subkey { subkey, lifespan }, defer err
    else if not (subkey.get_subkey_binding()?.sig?.get_framed_output())
      err = new Error "Cannot sign with subkey --- don't have private key and can't replay"
    cb err

  #--------------------------

  _sign_subkey : ({subkey, lifespan}, cb) ->
    sig = err = primary_binding = null

    # Don't want to try this for ECDH or ElGamal.
    if subkey.can_sign()
      await subkey._sign_primary_with_subkey { primary : @, lifespan }, defer err, primary_binding
    unless err?
      await @_sign_subkey_with_primary { subkey, lifespan, primary_binding }, defer err, sig
    unless err?
      SKB = packetsigs.SubkeyBinding
      ps = new SKB { primary : @, sig, direction : SKB.DOWN }
      subkey.push_sig ps
    cb err

  #--------------------------

  _sign_primary_with_subkey : ({primary, lifespan}, cb) ->
    payload = Buffer.concat [ primary.to_signature_payload(), @to_signature_payload() ]
    sig = new Signature {
      type : C.sig_types.primary_binding
      key : @key
      hashed_subpackets : [
        new S.CreationTime(lifespan.generated)
      ],
      unhashed_subpackets : [
        new S.Issuer(@get_key_id())
      ]}

    # We put these as signature subpackets, so we don't want to frame them;
    # they already come with framing as a result of their placement in
    # the signature.  This is a bit of a hack, but it's OK for now.
    await sig.write_unframed payload, defer err, sig_unframed
    cb err, sig_unframed

  #--------------------------

  _sign_subkey_with_primary : ({subkey, lifespan, primary_binding}, cb) ->
    payload = Buffer.concat [ @to_signature_payload(), subkey.to_signature_payload() ]

    unhashed_subpackets = [ new S.Issuer(@get_key_id()) ]
    # This is optional, especially for ECDH or ElGamal
    if primary_binding?
      unhashed_subpackets.push (new S.EmbeddedSignature { rawsig : primary_binding })

    sig = new Signature {
      type : C.sig_types.subkey_binding,
      @key,
      hashed_subpackets : [
        new S.CreationTime(lifespan.generated)
        new S.KeyExpirationTime(lifespan.expire_in)
        new S.KeyFlags([subkey.flags])
      ],
      unhashed_subpackets
    }

    await sig.write payload, defer err
    cb err, sig

  #--------------------------

  merge_private : (k2) ->
    @skm = k2.skm

  #--------------------------

  @parse_public_key : (slice, opts) -> (new Parser slice).parse_public_key opts

  #--------------------------

  @parse_private_key : (slice, opts) -> (new Parser slice).parse_private_key opts

  #--------------------------

  is_key_material : () -> true
  is_primary : -> not @opts?.subkey
  is_duplicate_primary : -> @_is_duplicate_primary
  set_duplicate_primary : () -> @_is_duplicate_primary = true
  ekid : () -> @key.ekid()
  can_sign : () -> @key.can_sign()
  is_locked : () -> (not @key.has_private()) and @skm? and @skm.is_locked()

  has_private : () -> @has_unlocked_private() or @has_locked_private()
  has_locked_private : () -> (@skm and @skm.has_private())
  has_unlocked_private : () -> @key.has_private()
  has_secret_key_material : () -> @skm?

  #--------------------------

  validity_check : (cb) ->
    await @key.validity_check defer err
    if err?
      msg = "In key #{@get_fingerprint().toString('hex')}: #{err.message}"
      err = new Error err
    cb err

  #--------------------------

  is_signed_subkey_of : (primary, opts) ->
    return false if @primary_flag
    need_upwards_sig = opts?.strict and @fulfills_flags C.key_flags.sign_data
    return @get_psc().is_signed_subkey_of(primary, need_upwards_sig)

  get_subkey_binding : () ->
    if @opts.subkey then @get_psc().get_subkey_binding() else null
  get_subkey_binding_signature_output : () ->
    @get_subkey_binding()?.sig?.get_framed_output()

  #--------------------------

  equal : (k2) -> bufeq_secure @ekid(), k2.ekid()

  #--------------------------

  # Open an OpenPGP key packet using the given passphrase
  #
  # @param {string} passphrase the passphrase in uft8
  #
  unlock : ({passphrase}, cb) ->
    passphrase = bufferify passphrase if passphrase?
    err = null

    unless @skm?
      err = new Error "Cannot unlock secret key -- no material!"
      return cb err

    pt = if @skm.s2k_convention is C.s2k_convention.none then @skm.payload
    else if (@skm.s2k.type is C.s2k.gnu_dummy) then null # no need to do anything here
    else if not passphrase?
      err = new Error "Key was locked, but no passphrase given"
      null
    else
      key = @skm.s2k.produce_key passphrase, @skm.cipher.key_size
      decrypt {
        ciphertext : @skm.payload,
        block_cipher_class : @skm.cipher.klass,
        iv : @skm.iv,
        key : key }

    if pt
      switch @skm.s2k_convention
        when C.s2k_convention.sha1
          end = pt.length - SHA1.output_size
          h1 = pt[end...]
          pt = pt[0...end]
          h2 = (new SHA1).bufhash pt
          err = new Error "bad private key passphrase (hash mismatch)" unless bufeq_secure(h1, h2)
        when C.s2k_convention.checksum, C.s2k_convention.none
          end = pt.length - 2
          c1 = pt.readUInt16BE end
          pt = pt[0...end]
          c2 = calc_checksum pt
          err = new Error "bad private key passphrase (checksum mismatch)" unless c1 is c2
      err = @key.read_priv(pt) unless err?

    cb err

  #-------------------

  get_all_key_flags    : ()      -> @_psc.get_all_key_flags()
  add_flags            : (v)     -> @flags |= v

  #-------------------

  fulfills_flags : (flags) ->

    # Never allow a revoked subkey to make its way out
    return false if @is_revoked()

    akf = @get_all_key_flags()

    # - Lots of cases to consider.  First, we see if the key is explicitly deemed
    #   appropriate for this sort of work, via a signature.
    # - Then we check if this is a single-purpose key like DSA, in which case it's implied(-ish)
    # - Finally, if no flags were supplied, and it's a primary key, then we assume it's
    #   good regardless (assuming you can actually perform the crypto op with the key)
    ret = ((akf & flags) is flags) or
       @key.fulfills_flags(flags) or
       (@is_primary() and (akf is 0) and ((@key.good_for_flags() & flags) is flags))

    return ret

  get_signed_userids         : () -> @get_psc().get_signed_userids()
  get_signed_user_attributes : () -> @get_psc().get_signed_user_attributes()
  is_self_signed             : () -> @get_psc().is_self_signed()

  #-------------------

  push_sig : (packetsig) ->
    @add_flags packetsig.sig.get_key_flags()
    super packetsig

  #-------------------

  mark_revoked : (sig) -> @revocation = sig
  is_revoked : () -> @revocation?

  #-------------------

  check_not_expired : ({now}) ->
    err = null
    if (e = @get_expire_time()?.expire_at) and e < now
      err = new Error "PGP key #{@get_fingerprint().toString('hex')} expired at #{e} but we checked for time #{now}"
    return err

  #-------------------

  is_preferable_to : (k2) ->
    e1 = @get_expire_time()
    e2 = k2.get_expire_time()
    e1.expire_at = Infinity unless e1.expire_at?
    e2.expire_at = Infinity unless e2.expire_at?

    ret = if e1.expire_at > e2.expire_at then true
    else if e1.expire_at < e2.expire_at then false
    else if e1.generated >= e2.generated then true
    else false
    return ret

  #-------------------

  # Returns non-zero expire time if it exists, otherwise null.
  get_expire_time : () ->
    if not (psc = @get_psc())? then null
    else if @is_primary() then @_get_expire_time_on_primary()
    else @_get_expire_time_on_subkey()

  #-------------------

  _get_expire_time_on_primary : () ->
    table = @get_psc().lookup.self_sigs_by_uid

    winner = null
    key_generated = @timestamp

    for uid,list of table

      uid_winner = null
      for packetsig in list when (sig = packetsig.sig)?
        expire_in = sig.get_key_expires()
        sig_generated = sig.when_generated()
        if not uid_winner? or uid_winner.sig_generated < sig_generated
          uid_winner = { expire_in, sig_generated }

      if uid_winner?
        uid_expire_in = uid_winner.expire_in or 0

        if (not winner?) or (uid_expire_in is 0) or (0 < winner < uid_expire_in)
          winner = uid_expire_in

    ret = { generated : @timestamp, expire_at : null, expire_in : null }
    if winner
      ret.expire_at = @timestamp + winner
      ret.expire_in = winner

    return ret

  #-------------------

  _get_expire_time_on_subkey : () ->
    list = @get_psc().lookup.subkey_binding
    return null unless list?.length

    winner = null

    # For subpacket signatures, only consider the signatures in the "down"
    # direction.  Don't consider the upwards reverse signatures
    for packetsig in list when packetsig.sig? and packetsig.is_down()
      {sig} = packetsig
      expire_in = sig.get_key_expires()
      generated = @timestamp

      # A zero or empty key expiration means it never expires;
      if expire_in and generated
        expire_at = generated + expire_in
        if not winner? or (winner.expire_at? and (winner.expire_at < expire_at))
          winner = { expire_at, generated, expire_in }
      else if (expire_in? and expire_in is 0) or not expire_in?
        winner = { generated, expire_in : null, expire_at : null }

    unless winner?
      winner = { generated : 0, expire_at : null, expire_in : null }

    return winner

#=================================================================================

class Parser

  #-------------------

  constructor : (@slice) ->
    @key = null

  #-------------------

  parse_public_key_v3 : () ->
    @timestamp = @slice.read_uint32()
    @expiration = @slice.read_uint16()
    @parse_public_key_mpis()

  #-------------------

  parse_public_key_v4 : () ->
    @timestamp = @slice.read_uint32()
    @parse_public_key_mpis()

  #-------------------

  parse_public_key_mpis: () ->
    @algorithm = @slice.read_uint8()
    A = C.public_key_algorithms
    klass = switch @algorithm
      when A.RSA, A.RSA_ENCRYPT_ONLY, A.RSA_SIGN_ONLY then RSA
      when A.DSA then DSA
      when A.ELGAMAL then ElGamal
      when A.ELGAMAL_SIGN_AND_ENCRYPT then ElGamalSE
      when A.ECDSA then ECDSA
      when A.ECDH then ECDH
      when A.EDDSA then EDDSA
      else throw new Error "Unknown key type: #{@algorithm}"
    [err, key, len] = klass.parse @slice.peek_rest_to_buffer()
    throw err if err?
    @slice.advance len
    key

  #-------------------

  # 5.5.2 Public-Key Packet Formats
  _parse_public_key : () ->
    switch (version = @slice.read_uint8())
      when C.versions.keymaterial.V3 then @parse_public_key_v3()
      when C.versions.keymaterial.V4 then @parse_public_key_v4()
      else throw new Error "Unknown public key version: #{version}"

  #-------------------

  parse_public_key : (opts) ->
    key = @_parse_public_key()
    new KeyMaterial { key, @timestamp, opts}

  #-------------------

  # 5.5.3.  Secret-Key Packet Formats
  #
  # See read_priv_key in openpgp.packet.keymaterial.js
  #
  parse_private_key : (opts) ->
    skm = new SecretKeyMaterial()
    key = @_parse_public_key()

    encrypted_private_key = true
    sym_enc_alg = null

    if (skm.s2k_convention = @slice.read_uint8()) is C.s2k_convention.none
      encrypted_private_key = false
    else
      if skm.s2k_convention in [ C.s2k_convention.sha1, C.s2k_convention.checksum ]
        sym_enc_alg = @slice.read_uint8()
        skm.s2k = (new S2K).read @slice
      else sym_enc_alg = skm.s2k_convention

    # There's a special GNU convention for showing that this key wasn't included.
    # This comes up when you export secret subkeys but keep the master key
    # hidden.
    if (skm.s2k_convention isnt C.s2k_convention.none) and (skm.s2k.type is C.s2k.gnu_dummy)
      skm.payload = null
    else
      if sym_enc_alg
        skm.cipher = symmetric.get_cipher sym_enc_alg
        iv_len = skm.cipher.klass.blockSize
        skm.iv = @slice.read_buffer iv_len
      skm.payload = @slice.consume_rest_to_buffer()

    new KeyMaterial { key, skm, @timestamp, opts }

#=================================================================================

exports.KeyMaterial = KeyMaterial

#=================================================================================

