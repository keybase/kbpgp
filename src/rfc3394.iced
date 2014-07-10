
{WordArray} = require 'triplesec'
{bufeq_secure} = require './util'

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

  [err, P, AES ] = setup { input : plaintext, key, cipher } 
  throw err if err?

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

setup = ( { input, key, cipher}) ->

  P = split64 WordArray.from_buffer input
  K = WordArray.from_buffer key
  {klass} = cipher
  AES = new klass K

  # Sanity-check the key size
  err = null
  if (a = cipher.key_size) isnt (b = key.length)
    err = new Error "Bad key, needed #{a} bytes, but got #{b}"

  return [err, P, AES ]

#================================================================================

#
# RFC 3394, Section 2.2.2 --- Key Unwrap
#    http://tools.ietf.org/html/rfc3394#section-2.2.2
#
# @param {Buffer} ciphertext The ciphertext to decrypt
# @param {Buffer} key the Key to encrypt with
# @param {Object} cipher The cipher object, which contains a `klass` saying which
#   class to use, and also a `key_size`; As returned from `symmetric.get_cipher`
# @return {Array<Error,Buffer>} the plaintext or an Error if the integrity check failed
#
exports.unwrap = unwrap = ({ciphertext, key, cipher}) ->

  [err, C, AES, n] = setup { input : ciphertext, key, cipher }
  return [err, null] if err?

  # 1) Initialize Variables
  A = C[0]
  R = C[1...]

  # 2) Calculate Intermediate values
  t = new WordArray [0, 6*R.length]
  for j in [0...6]
    for r,i in R by -1
      A.xor(t,{})
      B = A.clone().concat(r)
      AES.decryptBlock B.words
      A = B.slice(0,2)
      R[i] = B.slice(2,4)
      t.words[1]--

  # 3) Output the results
  if A.equal IV
    P = new WordArray []
    P.concat(r) for r in R
    [ null, P.to_buffer() ]
  else
    [ (new Error "integrity check failure; got bad IV in decryption"), null ]

#================================================================================

