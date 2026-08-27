{nbs,BigInteger} = require '../../lib/bn'

#=================================================================

exports.valid_mod_inverse_returns_inverse = (T, cb) ->
  cases = [
    { a : '3', m : '257', inverse : '86' }
    { a : '10', m : '17', inverse : '12' }
    { a : '101', m : '257', inverse : '28' }
  ]

  for c in cases
    a = nbs c.a
    m = nbs c.m
    inv = a.modInverse m
    T.equal inv.toString(), c.inverse, "#{c.a}^-1 mod #{c.m}"
    T.equal a.multiply(inv).mod(m).toString(), '1', "#{c.a} * inverse == 1 mod #{c.m}"
  cb()

#=================================================================

exports.invalid_mod_inverse_returns_zero_when_gcd_is_not_one = (T, cb) ->
  cases = [
    { a : '2', m : '4' }
    { a : '6', m : '9' }
    { a : '101', m : '101' }
    { a : '202', m : '101' }
    { a : '3', m : '0' }
  ]

  for c in cases
    a = nbs c.a
    m = nbs c.m
    inv = a.modInverse m
    T.equal inv.signum(), 0, "#{c.a}^-1 mod #{c.m} returned zero"
    T.equal inv.toString(), '0'
    unless m.signum() is 0
      T.assert not(a.gcd(m).equals(BigInteger.ONE)), "#{c.a} and #{c.m} are not coprime"
  cb()

#=================================================================
