
C = require('../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
RSA = require('../rsa').Pair
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{make_time_packet,uint_to_buffer,calc_checksum} = require '../util'
{encrypt} = require '../cfb'
{Packet} = require './base'
{UserID} = require './userid'
{Signature} = require './signature'
{encode} = require '../encode/armor'
{S2K} = require '../s2k'
{symmetric} = require '../symmetric'

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
      new Buffer([0]),
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

  _self_sign_key : (cb) ->
    pk = @public_body()
    uid8 = @uidp.utf8()

    # RFC 4480 5.2.4 Computing Signatures Over a Key
    x = [
      new Buffer([ C.signatures.key ] ),
      uint_to_buffer(16, pk.length),
      pk,
      new Buffer([ C.signatures.userid ]),
      uint_to_buffer(32, uid8.length),
      uid8
    ]
    payload = Buffer.concat x

    spkt = new Signature @
    await spkt.write C.sig_subpacket.issuer, payload, defer err, sig
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

  @parse_public_key : (slice) -> 
    p = (new Parser slice)
    p.parse_public_key()
    new KeyMaterial { key : p.key }

  #--------------------------

  @parse_private_key : (slice) -> 
    p = (new Parser slice)
    p.parse_private_key()
    new KeyMaterial { key : p.key, skm : p.secret_key_material() }
  
#=================================================================================

class Parser

  #-------------------
  
  constructor : (@slice) ->
    @pub = null

  #-------------------

  parse_public_key_v3 : () ->
    @creationTime = new Date (@slice.read_uint32() * 1000)
    @expiration = @slice.read_uint16()
    @parse_public_key_inner()

  #-------------------
  
  parse_public_key_v4 : () ->
    @creationTime = new Date (@slice.read_uint32() * 1000)
    @parse_public_key_inner()

  #-------------------
  
  parse_public_key_inner : () ->
    @algorithm = @slice.read_uint8()
    A = C.public_key_algorithms
    [err, @key, len ] = switch @algorithm
      when A.RSA, A.RSA_ENCRYPT_ONLY, A.RSA_SIGN_ONLY then RSA.parse @slice.peek_rest_to_buffer()
      else throw new Error "Can only deal with RSA right now"
    throw err if err?
    @slice.advance len

  #-------------------
  
  # 5.5.2 Public-Key Packet Formats
  parse_public_key : () ->
    switch (version = @slice.read_uint8())
      when C.versions.keymaterial.V3 then @parse_public_key_v3()
      when C.versions.keymaterial.V4 then @parse_public_key_v4()
      else throw new Error "Unknown public key version: #{version}"

  #-------------------

  secret_key_material : () ->
    { @enc_mpi_data, @iv, @checksum, @s2k, @enc_class, @s2k_convention }

  #-------------------

  # 5.5.3.  Secret-Key Packet Formats
  #
  # See read_priv_key in openpgp.packet.keymaterial.js
  #
  parse_private_key : () ->
    @parse_public_key()

    encrypted_private_key = true
    sym_enc_alg = null

    if (@s2k_convention = @slice.read_uint8()) is 0 then encrypted_private_key = false
    else if @s2k_convention in [ C.s2k_convention_sha1 or C.s2k_convention.checksum ]
      sym_enc_alg = @slice.read_uint8()
      @s2k = (new S2K).read @slice
    else sym_enc_alg = @s2k_convention

    if sym_enc_alg
      @enc_class = symmetric.get_class sym_enc_alg
      iv_len = @enc_class.blockSize
      @iv = @slice.read_buffer iv_len

    if (@s2k_convention isnt C.s2k_convention.none) and (@s2k.type is C.s2k.gnu)
      @enc_mpi_data = null
    else if encrypted_private_key
      @enc_mpi_data = @slice.consume_rest_to_buffer()
    else
      [err,len] = @key.add_priv @slice.peek_rest_to_buffer()
      throw err if err?
      @slice.advance len
      @checskum = @slice.readUInt16()

#=================================================================================

exports.KeyMaterial = KeyMaterial

#=================================================================================

