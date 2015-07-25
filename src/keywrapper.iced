
C = require('./const')

#=================================================================

class Lifespan
  constructor : ( {@generated, @expire_in}) ->
    # @expire_in is null if the key has no expire time.
    if @expire_in == undefined
      @expire_in = C.default_key_expire_in

  expires_earlier_than : (l2) ->
    if not(l2.expire_in) and @expire_in then true
    else if @expire_in and not(l2.expire_in) then false
    else if not(@expire_in) and not(l2.expire_in) then false
    else (@generated + @expire_in) < (l2.generated + l2.expire_in)

  copy : () -> new Lifespan { @generated, @expire_in }

#=================================================================

# @param {RSA::Pair} key The raw RSA (or DSA) key
# @param {Lifespan} lifespan The lifespan of the key
# @param {openpgp.KeyMaterial} _pgp The PGP KeyMaterial wrapper around the underlying key
# @param {keybase.KeyMaterial} _keybase The Keybase KeyMaterial wrapper around the underlying key,
#    this feature is currently defunct.
# @param {number} flags Only set on key generation; otherwise, you need
#    to look inside the keys for the appropriate signature.
#
class KeyWrapper
  constructor : ({@key, @lifespan, @_pgp, @_keybase, @flags}) ->
  ekid : () -> @key.ekid()

  # Overwrite this key wrapper with kw2 unless we expire later than
  # kw2
  overwrite_with : (kw2) ->
    unless kw2.lifespan.expires_earlier_than @lifespan
      {@key, @lifespan, @_pgp, @_keybase, @flags} = kw2

#=================================================================

class Subkey extends KeyWrapper
  constructor : ({key, flags, _pgp, _keybase, @desc, lifespan, @primary}) ->
    super { key, lifespan, flags, _pgp, _keybase }

#=================================================================

class Primary extends KeyWrapper
  constructor : ({key, lifespan, flags, _pgp, _keybase}) ->
    super { key, lifespan, flags, _pgp, _keybase }

#=================================================================

exports.Lifespan = Lifespan
exports.Subkey = Subkey
exports.Primary = Primary
