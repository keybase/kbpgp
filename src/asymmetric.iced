
C = require('./const').openpgp.public_key_algorithms
{RSA} = require './rsa'
{DSA} = require './dsa'
{ElGamal} = require './elgamal'
{ECDSA} = require './ecc/ecdsa'
{ECDH} = require './ecc/ecdh'

#============================================================

exports.get_class = (n) ->
  switch n
    when C.RSA, C.RSA_ENCRYPT_ONLY, C.RSA_SIGN_ONLY then RSA
    when C.ELGAMAL then ElGamal
    when C.DSA then DSA
    when C.ECDSA then ECDSA
    when C.ECDH then ECDH
    else throw new Error "unknown public key system: #{n}"

#============================================================
