{CAST5} = require '../src/cast5'
{WordArray} = require 'triplesec'
{AES} = require('triplesec').ciphers
{encrypt,decrypt} = require '../src/cfb'

buf_to_words = (b) -> (WordArray.from_buffer b).words
words_to_buf = (w) -> (new WordArray w).to_buffer()

key = new Buffer "583d18c32d8857a627ea3e86d6feada8", "hex"
iv = new Buffer 'fe40e836b0e9b193aabbccdd11223344', 'hex'
dat = new Buffer "8bb2a710bb8418711d987be3dce7ae416cf2357994fa7f70259b08691101c8c5", "hex"
aes = new AES WordArray.from_buffer(key)
#ciphertext = encrypt { block_cipher_class : AES, key, iv, plaintext : dat }   
block = buf_to_words dat
aes.encryptBlock block
ciphertext = words_to_buf block
console.log ciphertext.toString 'hex'
console.log ciphertext.length
console.log dat.length
