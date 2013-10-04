
C = require('./const').symmetric_key_algorithms
triplesec = require 'triplesec'
{AES} = triplesec.ciphers

exports.get_class = (n) ->
  switch n
    when C.AES128, C.AES192, C.AES256 then AES
    when C.CAST5
      throw new Error "Have not implemented CAST5 yet"
    else
      throw new Error "unknown cipher: #{n}"
