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

#=================================================================

OIDS = 
  nist_p256 : new Buffer [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 ]
  nist_p384 : new Buffer [0x2b, 0x81, 0x04, 0x00, 0x22 ]
  nist_p521 : new Buffer [0x2b, 0x81, 0x04, 0x00, 0x23 ]

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
