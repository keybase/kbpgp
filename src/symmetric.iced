
C = require('./const').symmetric_key_algorithms
triplesec = require 'triplesec'
{AES} = triplesec.ciphers

exports.get_cipher = (n) ->
  switch n
    when C.AES128 then { klass : AES, key_size : 16 }
    when C.AES192 then { klass : AES, key_size : 24 }
    when C.AES256 then { klass : AES, key_size : 32 }
    when C.CAST5
      throw new Error "Have not implemented CAST5 yet"
    else
      throw new Error "unknown cipher: #{n}"
