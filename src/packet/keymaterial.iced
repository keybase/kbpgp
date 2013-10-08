
C = require('../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
RSA = require('../rsa').Pair
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{unix_time,bufeq_secure,katch,make_time_packet,uint_to_buffer,calc_checksum} = require '../util'
{decrypt,encrypt} = require '../cfb'
{Packet} = require './base'
{UserID} = require './userid'
{CreationTime,Issuer,Signature} = require './signature'
{encode} = require '../encode/armor'
{S2K} = require '../s2k'
symmetric = require '../symmetric'

#=================================================================================

class KeyMaterial extends Packet

  constructor : ({@key, @timestamp, @userid, @passphrase, @skm}) ->
    @timepacket = make_time_packet @timestamp
    @uidp = new UserID @userid
    super()

  #--------------------------

  _write_private_enc : (bufs, priv) ->
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
    k = (new S2K).write @passphrase, salt, c  # expanded encryption key (via s2k)
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
    pub = @key.pub.serialize()
    bufs.push(
      new Buffer([ C.versions.keymaterial.V4 ]),   # Since PGP 5.x, this is prefered version
      @timepacket,
      new Buffer([ @key.type ]),
      pub
    )

  #--------------------------
  
  private_body : () ->
    bufs = []
    @_write_public bufs
    priv = @key.priv.serialize()
    if @passphrase? then @_write_private_enc   bufs, priv
    else                 @_write_private_clear bufs, priv
    ret = Buffer.concat bufs
    ret

  #--------------------------

  private_framed : () ->
    body = @private_body()
    @frame_packet C.packet_tags.secret_key, body

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

  #--------------------------
  
  public_framed : () ->
    body = @public_body()
    @frame_packet C.packet_tags.public_key, body

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

  _self_sign_key : (cb) ->
    payload = Buffer.concat [ @to_signature_payload(), @uidp.to_signature_payload() ]

    sigpkt = new Signature { 
      type : C.sig_types.issuer,
      key : @key,
      hashed_subpackets : [
        new CreationTime(unix_time()),
        new Issuer(@get_key_id())
      ]}
      
    await sigpkt.write payload, defer err, sig
    cb err, sig

  #--------------------------

  export_keys : ({armor}, cb) ->
    err = ret = null
    await @_self_sign_key defer err, sig
    ret = @_encode_keys { sig, armor } unless err?
    cb err, ret

  #--------

  _encode_keys : ({ sig, armor }) ->
    uidp = @uidp.write()
    {private_key, public_key} = C.message_types
    # XXX always armor for now ... in the future maybe allow binary output.. See Issue #6
    return {
      public  : encode(public_key , Buffer.concat([ @public_framed() , uidp, sig ]))
      private : encode(private_key, Buffer.concat([ @private_framed(), uidp, sig ]))
    }

  #--------------------------

  @parse_public_key : (slice) -> (new Parser slice).parse_public_key()

  #--------------------------

  @parse_private_key : (slice) -> (new Parser slice).parse_private_key()
  
  #--------------------------

  is_key_material : () -> true

  #--------------------------

  # Open an OpenPGP key packet using the given passphrase
  #
  # @param {string} passphrase the passphrase in uft8
  # 
  open : ({passphrase}, cb) ->
    err = null

    pt = if @skm.s2k_convention isnt C.s2k_convention.none
      decrypt { 
        ciphertext : @skm.payload,
        block_cipher_class : @skm.cipher.klass, 
        iv : @skm.iv, 
        key : @skm.s2k.produce_key passphrase, @skm.cipher.key_size }
    else pt = @skm.payload

    switch @skm.s2k_convention
      when C.s2k_convention.sha1
        end = pt.length - 20
        h1 = pt[end...]
        pt = pt[0...end]
        h2 = (new SHA1).bufhash pt
        err = new Error "hash mismatch" unless bufeq_secure(h1, h2)
      when C.s2k_convention.checksum, C.s2k_convention.none
        end = pt.length - 2
        c1 = pt.readUInt32BE end
        pt = pt[0...end]
        c2 = calc_checksum pt
        err = new Error "checksum mismatch" unless c1 is c2

    err = @pk.read_priv(pt) unless err?
    cb err

#=================================================================================

class Parser

  #-------------------
  
  constructor : (@slice) ->
    @key = null

  #-------------------

  parse_public_key_v3 : () ->
    @creationTime = new Date (@slice.read_uint32() * 1000)
    @expiration = @slice.read_uint16()
    @parse_public_key_mpis()

  #-------------------
  
  parse_public_key_v4 : () ->
    @creationTime = new Date (@slice.read_uint32() * 1000)
    @parse_public_key_mpis()

  #-------------------
  
  parse_public_key_mpis: () ->
    @algorithm = @slice.read_uint8()
    A = C.public_key_algorithms
    [err, key, len ] = switch @algorithm
      when A.RSA, A.RSA_ENCRYPT_ONLY, A.RSA_SIGN_ONLY then RSA.parse @slice.peek_rest_to_buffer()
      else throw new Error "Can only deal with RSA right now"
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

  parse_public_key : () ->
    key = @_parse_public_key()
    new KeyMaterial { key }

  #-------------------

  # 5.5.3.  Secret-Key Packet Formats
  #
  # See read_priv_key in openpgp.packet.keymaterial.js
  #
  parse_private_key : () ->
    skm = {}
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

    if sym_enc_alg
      skm.cipher = symmetric.get_cipher sym_enc_alg
      iv_len = skm.cipher.klass.blockSize
      skm.iv = @slice.read_buffer iv_len

    if (skm.s2k_convention isnt C.s2k_convention.none) and (skm.s2k.type is C.s2k.gnu)
      skm.payload = null
    else 
      skm.payload = @slice.consume_rest_to_buffer()
    new KeyMaterial { key, skm }

#=================================================================================

exports.KeyMaterial = KeyMaterial

#=================================================================================

