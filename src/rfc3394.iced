
{WordArray} = require 'triplesec'

#================================================================================

# RFC 3394, Section 2.2.3.1 -- Initial Value
#  http://tools.ietf.org/html/rfc3394#section-2.2.3.1
IV = WordArray.from_hex "A6A6A6A6A6A6A6A6"

#================================================================================

# Split a WordArray into an array of smaller 64-bit buffers
split64 = (wa) -> wa.split (wa.words.length >> 1)

#================================================================================

#
# RFC 3394, Section 2.2.1 --- Key Wrap
#    http://tools.ietf.org/html/rfc3394#section-2.2.1
#
# @param {Buffer} plaintext The plaintext to encrypt
# @param {Buffer} key the Key to encrypt with
# @param {Object} cipher The cipher object, which contains a `klass` saying which
#   class to use, and also a `key_size`; As returned from `symmetric.get_cipher`
# @return {Buffer} the ciphertext, all wrapped
#
exports.wrap = wrap = ({plaintext, key, cipher}) ->

  P = split64 WordArray.from_buffer plaintext
  K = WordArray.from_buffer key
  {klass} = cipher
  AES = new klass K

  # Sanity-check the key size
  unless (a = cipher.key_size) is (b = key.length)
    throw new Error "Bad key, needed #{a} bytes, but got #{b}"

  # n is the number of 64-bit chunks the plaintext can be split into.
  n = P.length

  # 1) Initialize Variables
  A = IV
  R = P

  # 2) Calculate intermediate values
  t = new WordArray [0,0]
  for j in [0...6]
    for r,i in R
      t.words[1]++
      B = A.clone().concat(r)
      AES.encryptBlock B.words
      A = B.slice(0,2)
      R[i] = B.slice(2,4)
      A.xor(t, {})

  # 3) Output the results
  C = A
  C.concat(r) for r in R
  return C.to_buffer()

#================================================================================

test = () ->
  {AES} = require('triplesec').ciphers
  {get_cipher} = require './symmetric'
  plaintext = new Buffer "00112233445566778899AABBCCDDEEFF", "hex"
  key = new Buffer "000102030405060708090A0B0C0D0E0F", "hex"
  cipher = { klass : AES , key_size : 16 }
  console.log wrap({ plaintext, key, cipher }).toString 'hex'
