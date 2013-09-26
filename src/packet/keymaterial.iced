
C = require './const'
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{buf_hash} = require './util'
{encrypt} = require './cfb'

#========= ========= ========= ========= ========= ========= ========= ========= ========= =========

class KeyMaterial

  constructor : (@key) ->

  #--------------------------

  _write_private_enc : (bufs, password) ->
    bufs.push new Buffer [ 
      254,                                  # Indicates s2k with SHA1 checksum
      C.symmetric_key_algorithms.AES256,    # Sym algo used to encrypt
      C.s2k.salt_iter,                      # s2k salt+iterative
      C.hash_algorithms.SHA256              # s2k hash algo
    ]
    sha1hash = (new SHA1).bufhash priv      # checksum of the cleartext MPIs
    salt = native_rng 8                     # 8 bytes of salt
    bufs.push salt 
    c = 96
    bufs.push new Buffer [ c ]              # ??? translates to a count of 65336 ???
    k = (new S2K).write password, salt, c   # expanded encryption key (via s2k)
    ivlen = AES.blockSize                   # ivsize = msgsize
    iv = native_rng ivlen                   # Consider a truly random number in the future
    bufs.push iv                            # push the IV on before the ciphertext

    # horrible --- 'MAC' then encrypt :(
    plaintext = Buffer.concat [ priv, sha1hash ]   

    # Encrypt with CFB/mode + AES.  Use the expanded key from s2k
    ct = encrypt { block_cipher_class : AES, key : k, plaintext, iv } 
    bufs.push ct

  #--------------------------
  
  write_private : ({password, timepacket}) ->
    priv = @key.priv.serialize()
    pub  = @key.pub.serialize()
    bufs = [
      new Buffer [ @key.type ]
      timepacket
      pub
    ]

    if password? then @_write_private_enc bufs, password
    else              @_write_private_clear bufs

    Buffer.concat bufs

  #--------------------------
