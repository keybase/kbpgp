
{nbv,nbi,BigInteger,nbits} = require 'bn'
{buffer_to_ui8a} = require './util'

#=================================================================

# Generate a BigInt from a string s, and a base.
# @param {String} s the BigInt
# @param {number} base the base that the string is in
# @return {BigInteger} the result
nbs = (s, base = 10) ->
  r = nbi()
  r.fromString s, base

#================================================================

mpi_byte_length = (bn) -> bn.toByteArray().length

#================================================================

#
# @param {BitInteger} bn An input big integer
# @return {Buffer} A buffer-representation of the multi-precision integer
#
toMPI = (bn) ->
  ba = bn.toByteArray()
  # The top byte isn't a full byte, so figure out how many bits it takes
  size = (ba.length - 1) * 8 + nbits(ba[0])
  hdr = new Buffer 2
  hdr.writeUInt16BE size, 0
  Buffer.concat [ hdr, new Buffer(ba) ]

#================================================================

mpi_from_buffer = (raw) ->
  err = i = null
  if raw.length < 2
    err = new Error "need at least 2 bytes; got #{raw.length}"
  else
    hdr = new Buffer raw[0...2]
    raw = raw[2...]
    n_bits = hdr.readUInt16BE 0
    n_bytes = Math.ceil n_bits/8
    if raw.length < n_bytes
      err = new Error "MPI said #{n_bytes} bytes but only got #{raw.length}"
    else
      i = nbi().fromBuffer raw[0...n_bytes]
      raw = raw[n_bytes...]
  [err, i, raw, (n_bytes + 2) ]

#================================================================

mpi_to_padded_octets = (bn, base) ->
  n = base.mpi_byte_length()
  ba = bn.toByteArray()
  diff = (n - ba.length)
  pad = new Buffer(0 for i in [0...diff])
  Buffer.concat [ pad, new Buffer(ba) ]

#================================================================

# Shift a buffer right by nbits
buffer_shift_right = (buf, nbits) ->
  nbytes = (nbits >> 3)
  rem = nbits % 8
  buf = buf[0...(buf.length - nbytes)]
  l = buf.length
  mask = (1 << rem) - 1
  for i in [(l-1)..0]
    c = (buf.readUInt8(i) >> rem)
    if i > 0
      nxt = buf.readUInt8(i-1) & mask
      c |= (nxt << (8 - rem))
    buf.writeUInt8(c, i)
  buf

#================================================================

bn_from_left_n_bits = (raw, bits) ->
  if raw.length*8 <= bits
    nbi().fromBuffer(raw)
  else
    rem = bits % 8
    bytes = (bits >> 3) + (if rem then 1 else 0)
    buf = raw[0...bytes]
    ret = nbi().fromBuffer(buf)
    if rem > 0
      ret = ret.shiftRight(8 - rem)
    ret

#================================================================

exports.toMPI = toMPI
exports.nbs = nbs
exports.mpi_from_buffer = mpi_from_buffer
exports.mpi_to_padded_octets = mpi_to_padded_octets
exports.buffer_shift_right = buffer_shift_right
exports.bn_from_left_n_bits = bn_from_left_n_bits

# Monkey-patch the BigInteger prototyp, for convenience...
BigInteger.prototype.to_mpi_buffer = () -> toMPI @
BigInteger.prototype.mpi_byte_length = () -> mpi_byte_length @
BigInteger.prototype.to_padded_octets = (base) -> mpi_to_padded_octets @, base

exports.BigInteger = BigInteger
exports.nbi = nbi
exports.nbv = nbv
exports.nbits = nbits

#================================================================
