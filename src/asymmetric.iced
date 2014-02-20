
C = require('./const').openpgp.public_key_algorithms
{RSA} = require './rsa'
{DSA} = require './dsa'
{ElGamal} = require './elgamal'

exports.get_class = (n) ->
  switch n
    when C.RSA, C.RSA_ENCRYPT_ONLY, C.RSA_SIGN_ONLY then RSA
    when C.ELGAMAL then ElGamal
    when C.DSA then DSA
    else throw new Error "unknown public key system: #{n}"

#============================================================
