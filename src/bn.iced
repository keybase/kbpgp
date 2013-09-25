
{nbv,nbi,BigInteger,nbits} = require('openpgp').bigint

#=================================================================

# Generate a BigInt from a string s, and a base.
# @param {String} s the BigInt
# @param {number} base the base that the string is in
# @return {BigInteger} the result
nbs = (s, base = 10) ->
  r = nbi()
  r.fromString s, base
  r

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

exports.toMPI = toMPI
exports.nbs = nbs

# Monkey-patch the BigInteger prototyp, for convenience...
BigInteger.prototype.to_mpi_buffer = () -> toMPI @

#================================================================

