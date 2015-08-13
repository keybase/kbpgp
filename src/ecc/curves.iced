{BigInteger} = require '../bn'
base = require 'keybase-ecurve'
{uint_to_buffer} = require '../util'
{SlicerBuffer} = require '../openpgp/buffer'
{SRF} = require '../rand'
bn = require '../bn'

#=================================================================

exports.H = H = (x) -> BigInteger.fromHex x.split(/\s+/).join('')

#=================================================================

exports.Curve = class Curve extends base.Curve

  #----------------------------------

  constructor : ( { p, a, b, Gx, Gy, n, h, @oid} ) ->
    h or= BigInteger.ONE
    super p, a, b, Gx, Gy, n, h

  #----------------------------------

  mkpoint : ({x,y}) ->
    base.Point.fromAffine @, x, y

  #----------------------------------

  nbits : () -> @p.bitLength()

  #----------------------------------

  mpi_bit_size : () ->
    # Rounding up needed for p521, and 3 bits needed to represent the leading 0x4
    2*@mpi_coord_bit_size() + 3

  #----------------------------------

  mpi_coord_byte_size : () -> Math.ceil(@nbits()/8)
  mpi_coord_bit_size : () -> @mpi_coord_byte_size()*8

  #----------------------------------

  # Read a point from an MPI as specified in 
  #
  #   http://tools.ietf.org/html/rfc6637#section-6
  #   Section 6: Conversion Primitives
  # 
  # Throw an error if there's an issue.
  #
  _mpi_point_from_slicer_buffer : (sb) ->
    n_bits = sb.read_uint16()
    if n_bits isnt (b = @mpi_bit_size())
      throw new Error "Need #{b} bits for this curve; got #{n_bits}"
    if sb.read_uint8() isnt 0x4
      throw new Error "Can only handle 0x4 prefix for MPI representations"
    n_bytes = @mpi_coord_byte_size()
    [x,y] = [ BigInteger.fromBuffer(sb.read_buffer(n_bytes)), BigInteger.fromBuffer(sb.read_buffer(n_bytes)) ]
    point = @mkpoint { x, y} 
    unless @isOnCurve point
      throw new Error "Given ECC point isn't on the given curve; data corruption detected."
    [ null, point ]

  #----------------------------------

  mpi_point_from_buffer : (b) ->
    @mpi_point_from_slicer_buffer new SlicerBuffer b

  #----------------------------------

  mpi_point_from_slicer_buffer : (sb) ->
    err = point = null
    try 
      [err, point] = @_mpi_point_from_slicer_buffer sb
    catch e 
      err = e
    return [err, point ]

  #----------------------------------

  point_to_mpi_buffer_compact : (p) -> p.affineX.toBuffer @p.byteLength()

  #----------------------------------

  point_to_mpi_buffer : (p) ->
    sz = @mpi_coord_byte_size()
    ret = Buffer.concat [
      uint_to_buffer(16, @mpi_bit_size()),
      new Buffer([0x4]),
      p.affineX.toBuffer(sz),
      p.affineY.toBuffer(sz)
    ]
    ret

  #----------------------------------

  random_scalar : (cb) ->
    await SRF().random_zn @n.subtract(bn.nbv(2)), defer k
    k = k.add(bn.BigInteger.ONE)
    cb k

#=================================================================

# Curve parameters taken from here:
#
#  http://www.nsa.gov/ia/_files/nist-routines.pdf
#

# This one is specified in the base library....
# p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
#------------------------------------
exports.nist_p256 = nist_p256 = () ->
  p  = H("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF")
  a  = H("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC")
  b  = H("5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B")
  n  = H("FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551")
  Gx = H("6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296")
  Gy = H("4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5")
  new Curve { p, a, b, Gx, Gy, n, oid : OIDS.nist_p256 }

#------------------------------------

# p_384 = 2^384 − 2^128 − 2^96 + 2^32 − 1
exports.nist_p384 = nist_p384 = () ->
  p  = H('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 ffffffff')
  a  = H('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 fffffffc')
  b  = H('b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef')
  n  = H('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973')
  Gx = H('aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7')
  Gy = H('3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f')
  new Curve { p, a, b, Gx, Gy, n, oid : OIDS.nist_p384 }

#------------------------------------

# p_521 = 2^521 - 1
# a = p_521 - 3
exports.nist_p521 = nist_p521 = () ->
  p  = H('000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff')
  a  = H('000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffc')
  b  = H('00000051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00')
  n  = H('000001ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148 f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409')
  Gx = H('000000c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127 a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66')
  Gy = H('00000118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449 579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901 3fad0761 353c7086 a272c240 88be9476 9fd16650')
 
  new Curve { p, a, b, Gx, Gy, n, oid : OIDS.nist_p521 }
  
#------------------------------------

exports.brainpool_p256 = brainpool_p256 = () ->
  p  = H('a9fb57db a1eea9bc 3e660a90 9d838d72 6e3bf623 d5262028 2013481d 1f6e5377')
  a  = H('7d5a0975 fc2c3057 eef67530 417affe7 fb8055c1 26dc5c6c e94a4b44 f330b5d9')
  b  = H('26dc5c6c e94a4b44 f330b5d9 bbd77cbf 95841629 5cf7e1ce 6bccdc18 ff8c07b6')
  n  = H('a9fb57db a1eea9bc 3e660a90 9d838d71 8c397aa3 b561a6f7 901e0e82 974856a7')
  Gx = H('8bd2aeb9 cb7e57cb 2c4b482f fc81b7af b9de27e1 e3bd23c2 3a4453bd 9ace3262')
  Gy = H('547ef835 c3dac4fd 97f8461a 14611dc9 c2774513 2ded8e54 5c1d54c7 2f046997')
 
  new Curve { p, a, b, Gx, Gy, n, oid : OIDS.brainpool_p256 }
  
#------------------------------------

exports.brainpool_p384 = brainpool_p384 = () ->
  p  = H('8cb91e82 a3386d28 0f5d6f7e 50e641df 152f7109 ed5456b4 12b1da19 7fb71123 acd3a729 901d1a71 87470013 3107ec53')
  a  = H('7bc382c6 3d8c150c 3c72080a ce05afa0 c2bea28e 4fb22787 139165ef ba91f90f 8aa5814a 503ad4eb 04a8c7dd 22ce2826')
  b  = H('04a8c7dd 22ce2826 8b39b554 16f0447c 2fb77de1 07dcd2a6 2e880ea5 3eeb62d5 7cb43902 95dbc994 3ab78696 fa504c11')
  n  = H('8cb91e82 a3386d28 0f5d6f7e 50e641df 152f7109 ed5456b3 1f166e6c ac0425a7 cf3ab6af 6b7fc310 3b883202 e9046565')
  Gx = H('1d1c64f0 68cf45ff a2a63a81 b7c13f6b 8847a3e7 7ef14fe3 db7fcafe 0cbd10e8 e826e034 36d646aa ef87b2e2 47d4af1e')
  Gy = H('8abe1d75 20f9c2a4 5cb1eb8e 95cfd552 62b70b29 feec5864 e19c054f f9912928 0e464621 77918111 42820341 263c5315')
 
  new Curve { p, a, b, Gx, Gy, n, oid : OIDS.brainpool_p384 }

#------------------------------------

exports.brainpool_p512 = brainpool_p512 = () ->
  p  = H('aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07 cb308db3 b3c9d20e d6639cca 70330871 7d4d9b00 9bc66842 aecda12a e6a380e6 2881ff2f 2d82c685 28aa6056 583a48f3')
  a  = H('7830a331 8b603b89 e2327145 ac234cc5 94cbdd8d 3df91610 a83441ca ea9863bc 2ded5d5a a8253aa1 0a2ef1c9 8b9ac8b5 7f1117a7 2bf2c7b9 e7c1ac4d 77fc94ca')
  b  = H('3df91610 a83441ca ea9863bc 2ded5d5a a8253aa1 0a2ef1c9 8b9ac8b5 7f1117a7 2bf2c7b9 e7c1ac4d 77fc94ca dc083e67 984050b7 5ebae5dd 2809bd63 8016f723')
  n  = H('aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07 cb308db3 b3c9d20e d6639cca 70330870 553e5c41 4ca92619 41866119 7fac1047 1db1d381 085ddadd b5879682 9ca90069')
  Gx = H('81aee4bd d82ed964 5a21322e 9c4c6a93 85ed9f70 b5d916c1 b43b62ee f4d0098e ff3b1f78 e2d0d48d 50d1687b 93b97d5f 7c6d5047 406a5e68 8b352209 bcb9f822')
  Gy = H('7dde385d 566332ec c0eabfa9 cf7822fd f209f700 24a57b1a a000c55b 881f8111 b2dcde49 4a5f485e 5bca4bd8 8a2763ae d1ca2b2f a8f05406 78cd1e0f 3ad80892')
 
  new Curve { p, a, b, Gx, Gy, n, oid : OIDS.brainpool_p512 }

#=================================================================

OIDS = 
  nist_p256 : new Buffer [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 ]
  nist_p384 : new Buffer [0x2b, 0x81, 0x04, 0x00, 0x22 ]
  nist_p521 : new Buffer [0x2b, 0x81, 0x04, 0x00, 0x23 ]
  brainpool_p256 :  new Buffer [ 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 ]
  brainpool_p384 :  new Buffer [ 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B ]
  brainpool_p512 :  new Buffer [ 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D ]

OID_LOOKUP = {}
for k,v of OIDS
  OID_LOOKUP[v.toString('hex')] = exports[k]

#=================================================================

exports.alloc_by_oid = (oid) ->
  oid = oid.toString('hex') if Buffer.isBuffer(oid)
  err = curve = null
  if (f = OID_LOOKUP[oid.toLowerCase()])? then curve = f()
  else err = new Error "Unknown curve OID: #{oid}"
  [err,curve]
  
#=================================================================

exports.alloc_by_nbits = (nbits) ->
  ret = err = null
  nbits or= 256
  f = switch nbits 
    when 256 then nist_p256
    when 384 then nist_p384
    when 521 then nist_p521
    else null
  if f? then ret = f()
  else err = new Error "No curve for #{nbits} bits"
  return [ err, ret ]

#=================================================================
