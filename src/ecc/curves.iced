{BigInteger} = require 'bn'
{Curve,Point,getCurveByName} = require 'keybase-ecurve'

#=================================================================

exports.H = H = (x) -> BigInteger.fromHex x.split(/\s+/).join('')

#=================================================================

# Curve parameters taken from here:
#
#  http://www.nsa.gov/ia/_files/nist-routines.pdf
#

# This one is specified in the base library....
# p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
exports.nist_p256 = () -> getCurveByName('secp256r1')

#------------------------------------

# p_384 = 2^384 − 2^128 − 2^96 + 2^32 − 1
exports.nist_p384 = () ->
  p  = H('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 ffffffff')
  a  = H('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 fffffffc')
  b  = H('b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef')
  n  = H('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973')
  h  = BigInteger.ONE
  Gx = H('aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7')
  Gy = H('3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f')
  new Curve p, a, b, Gx, Gy, n, h

#------------------------------------

# p_521 = 2^521 - 1
# a = p_521 - 3
exports.nist_p521 = () ->
  p  = H('000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff')
  a  = H('000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffc')
  b  = H('00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00')
  n  = H('000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409')
  h  = BigInteger.ONE
  Gx = H('000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66')
  Gy = H('00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 3fad0761 353c7086 a272c240 88be9476 9fd16650')
  new Curve p, a, b, Gx, Gy, n, h

#=================================================================

