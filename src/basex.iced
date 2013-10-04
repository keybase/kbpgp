{nbv,nbi,BigInteger} = require('openpgp').bigint
{nbs} = require './bn'

#=====================================================================

class BaseX

  constructor: (@alphabet) ->
    @base = @alphabet.length
    @basebn = nbv @base
    @lookup = {}
    for a,i in @alphabet
      @lookup[a] = i

  encode: (buffer) ->
    num = nbi()
    num.fromString (new Uint8Array buffer), 256, true
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
    for char, index in str.split(//).reverse()
      unless (char_index = @lookup[char])?
        throw new Error('Value passed is not a valid Base58 string.')
      num = num.add base.multiply nbv char_index
      base = base.multiply @basebn
    new Buffer num.toByteArray()

#=====================================================================

exports.base58 = base58 = new BaseX '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

buf = new Buffer [1...40]
console.log buf.toString 'hex'
enc = base58.encode buf
console.log enc
dec = base58.decode enc
console.log dec.toString 'hex'