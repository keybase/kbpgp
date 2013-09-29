
C = require('../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{uint_to_buffer,calc_checksum} = require '../util'
{encrypt} = require '../cfb'
{Packet} = require './base'

#=================================================================================

class KeyMaterial extends Packet

  constructor : (@key, {@timepacket}) ->
    super()

  #--------------------------

  _write_private_enc : (bufs, priv, passphrase) ->
    bufs.push new Buffer [ 
      254,                                   # Indicates s2k with SHA1 checksum
      C.symmetric_key_algorithms.AES256,     # Sym algo used to encrypt
      C.s2k.salt_iter,                       # s2k salt+iterative
      C.hash_algorithms.SHA256               # s2k hash algo
    ]
    sha1hash = (new SHA1).bufhash priv       # checksum of the cleartext MPIs
    salt = native_rng 8                      # 8 bytes of salt
    bufs.push salt 
    c = 96
    bufs.push new Buffer [ c ]               # ??? translates to a count of 65336 ???
    k = (new S2K).write passphrase, salt, c  # expanded encryption key (via s2k)
    ivlen = AES.blockSize                    # ivsize = msgsize
    iv = native_rng ivlen                    # Consider a truly random number in the future
    bufs.push iv                             # push the IV on before the ciphertext

    # horrible --- 'MAC' then encrypt :(
    plaintext = Buffer.concat [ priv, sha1hash ]   

    # Encrypt with CFB/mode + AES.  Use the expanded key from s2k
    ct = encrypt { block_cipher_class : AES, key : k, plaintext, iv } 
    bufs.push ct

  #--------------------------

  _write_private_clear : (bufs, priv) ->
    bufs.push [ 
      new Buffer([0]),
      priv,
      uint_to_buffer(calc_checksum(priv), 16)
    ]

  #--------------------------

  _write_public : (bufs, timepacket) ->
    pub = @key.pub.serialize()
    bufs.push [
      new Buffer([ C.version.keymaterial.V4 ]),   # Since PGP 5.x, this is prefered version
      timepacket,
      new Buffer([ @key.type ]),
      pub
    ] 

  #--------------------------
  
  private_body : ({passphrase, timepacket}) ->
    bufs = []
    timepacket or= @timepacket
    @_write_public bufs, timepacket
    priv = @key.priv.serialize()
    if password? then @_write_private_enc   bufs, priv, passphrase
    else              @_write_private_clear bufs, priv
    Buffer.concat bufs

  #--------------------------

  private_framed : ( {passphrase, timepacket}) ->
    body = @private_body { passphrase, timepacket }
    @frame_packet C.packet_tags.public_key, body

  #--------------------------

  public_body : ({timepacket}) ->
    timepacket or= @timepacket
    bufs = []
    @_write_public bufs, timepacket
    Buffer.concat bufs

  #--------------------------

  get_fingerprint : () ->
    data = public_body()
    (new SHA1).bufhash Buffer.concat [
      new Buffer([ C.signatures.key ]),
      uint_to_buffer(16, data.length),
      data
    ]

  #--------------------------

  get_key_id : () -> @get_fingerprint()[12...20]

  #--------------------------
  
  public_framed : ( { timepacket }) ->
    body = @public_body { timepacket }
    @frame_packet C.packet_tags.public_key, body

  #--------------------------
  
#=================================================================================

