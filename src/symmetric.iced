
C = require('./const').openpgp.symmetric_key_algorithms
triplesec = require 'triplesec'
{AES} = triplesec.ciphers
{CAST5} = require './cast5'

exports.get_cipher = (n) ->
  switch n
    when C.AES128 then { klass : AES, key_size : 16 }
    when C.AES192 then { klass : AES, key_size : 24 }
    when C.AES256 then { klass : AES, key_size : 32 }
    when C.CAST5  then { klass : CAST5, key_size : CAST5.keySize }
    else
      throw new Error "unknown cipher: #{n}"
