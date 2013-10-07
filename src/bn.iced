
{nbv,nbi,BigInteger,nbits} = require('openpgp').bigint
{buffer_to_ui8a} = require './util'

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
      a = buffer_to_ui8a raw[0...n_bytes]
      raw = raw[n_bytes...]
      i = nbi()
      # the last 'true' is for 'unsigned', our hack to jsbn.js to 
      # workaround the bugginess of their sign bit manipulation.
      i.fromString a, 256, true
  [err, i, raw, (n_bytes + 2) ]

#================================================================

exports.toMPI = toMPI
exports.nbs = nbs
exports.mpi_from_buffer = mpi_from_buffer

# Monkey-patch the BigInteger prototyp, for convenience...
BigInteger.prototype.to_mpi_buffer = () -> toMPI @
BigInteger.prototype.mpi_byte_length = () -> mpi_byte_length @

#================================================================

