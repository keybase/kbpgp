
C = require('./const').openpgp.public_key_algorithms
{RSA} = require './rsa'

exports.get_class = (n) ->
  switch n
    when C.RSA, C.RSA_ENCRYPT_ONLY, C.RSA_SIGN_ONLY then RSA
    when ELGAMAL then throw new Error "no support yet for ElGamal"
    when DSA then throw new Error "no support yet for DSA"
    else throw new Error "unknown public key system: #{n}"
