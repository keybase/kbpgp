{nbv,nbi,BigInteger} = require 'bn'
{nbs} = require './bn'
{buffer_to_ui8a} = require './util'

#=====================================================================

class BaseX

  constructor: (@alphabet) ->
    @base = @alphabet.length
    @basebn = nbv @base
    @lookup = {}
    for a,i in @alphabet
      @lookup[a] = i

  encode: (buffer) ->
    num = nbi().fromBuffer buffer
    chars = while num.compareTo(BigInteger.ZERO) > 0
      [q,r] = num.divideAndRemainder @basebn
      c = @alphabet[r.intValue()]
      num = q
      c
    chars.reverse()
    pad = []
    for c in buffer
      if c is 0 then pad.push @alphabet[0]
      else break
    (pad.concat chars).join ''

  decode: (str) ->
    num = BigInteger.ZERO
    base = BigInteger.ONE
    i = 0
    for c,i in str
      break unless c is @alphabet[0]
    start = i
    pad = new Buffer (0 for i in [0...start])
    for c,i in str[start...] by -1
      unless (char_index = @lookup[c])?
        throw new Error('Value passed is not a valid BaseX string.')
      num = num.add base.multiply nbv char_index
      base = base.multiply @basebn
    Buffer.concat [pad, new Buffer(num.toByteArray()) ]

#=====================================================================

exports.base58 = base58 = new BaseX '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
exports.base32 = base32 = new BaseX 'abcdefghijkmnpqrstuvwxyz23456789'
exports.base91 = new BaseX("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()-_=+{}[]|;:,<>./?")

#=====================================================================

