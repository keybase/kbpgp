
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

  # Overwrite this key wrapper with kw2 if kw2's expiration date is later than
  # ours. If one of the two is revoked, always take the other, irrespective of
  # the expiration date.
  #
  # XXX: Dropping revokes is not a very safe thing to do with PGP keys. In our
  # case, we need past signatures that you made to remain valid, even if you
  # revoke parts of that key in the future. We're doing this merge only for
  # signatures made before we have more reliable key version pinning in place.
  overwrite_with_omitting_revokes : (kw2) ->
    if kw2._pgp.is_revoked()
      return
    if @_pgp.is_revoked() or @lifespan.expires_earlier_than kw2.lifespan
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
