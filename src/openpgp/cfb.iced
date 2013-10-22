
{ciphers,WordArray} = require 'triplesec'
{AES} = ciphers

#=======================================================================

# An implementation of the normal version of CFB mode, for encryption.
# Either provide a `block_cipher_class` and a `key`, or just a `cipher`
# object if you already have one on hand.
#
# @param {Class} block_cipher_class The class of the block cipher to use in CFB mode. (default=AES)
# @param {Buffer} key the Key to encrypt with
# @param {BlockCipher} cipher A block cipher to use if you have one on hand
# @param {Buffer} plaintext the plaintext to encrypt
# @param {Buffer} iv the initial value to use for iv
# @return {Buffer} the cipher text
#
encrypt = ({block_cipher_class, key, cipher, plaintext, iv}) ->
  block_cipher_class or= AES
  cipher or= new block_cipher_class WordArray.from_buffer key 
  block_size = cipher.blockSize
  c = WordArray.from_buffer iv[0...block_size]
  pos = 0
  list = while plaintext.length > pos
    cipher.encryptBlock c.words, 0
    e = c
    c = WordArray.from_buffer plaintext[pos...(pos+block_size)]
    e.xor c, {n_words : c.words.length }
    pos += block_size
    c = e
    e.to_buffer()
  out = Buffer.concat list
  out[0...(plaintext.length)]

#=======================================================================

# An implementation of the normal version of CFB mode, for decryption
#
# @param {Class} block_cipher_class The class of the block cipher to use in CFB mode. (default=AES)
# @param {Buffer} key the Key to encrypt with
# @param {BlockCipher} cipher A block cipher to use if you have one on hand
# @param {Buffer} ciphertext the ciphertext to decyrpt
# @param {Buffer} iv the initial value to use for iv
# @return {Buffer} the plaintext
#
decrypt = ({block_cipher_class, key, cipher, ciphertext, iv}) ->
  block_cipher_class or= AES
  cipher or= new block_cipher_class WordArray.from_buffer key
  block_size = cipher.blockSize
  iv or= new Buffer (0 for i in [0...block_size])
  b = WordArray.from_buffer iv[0...block_size]
  pos = 0
  list = while ciphertext.length > pos
    cipher.encryptBlock b.words, 0
    d = b
    b = WordArray.from_buffer ciphertext[pos...(pos+block_size)]
    d.xor b, {}
    pos += block_size
    d.to_buffer()
  out = Buffer.concat list
  out[out...(ciphertext.length)]

#=======================================================================

exports.encrypt = encrypt
exports.decrypt = decrypt

#=======================================================================

