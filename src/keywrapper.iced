
C = require('./const')

#=================================================================

class Lifespan
  constructor : ( {@generated, @expire_in}) ->
    @expire_in or= C.default_key_expire_in

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
  kid : () -> @key.kid()
  ekid : () -> @key.ekid()

#=================================================================

class Subkey extends KeyWrapper
  constructor : ({key, flags, _pgp, _keybase, @desc, lifespan, @primary}) -> 
    super { key, lifespan, flags, _pgp, _keybase }

#=================================================================

class Primary extends KeyWrapper
  constructor : ({key, lifespan, flags, _pgp, _keybase}) -> 
    super { key, lifespan, flags, _pgp, _keybase }

#=================================================================

class UserId
  constructor : ({@openpgp, @components}) ->
    @_parse() unless @components?

  get_openpgp : () -> @openpgp 

  _parse : () ->
    x = ///
      ^([^(<]*?)       # The beginning name of the user (no comment or key)
      \s+              # Separation before the key or comment
      (\((.*?)\)\s+)?  # The optional comment
      <(.*)?>$         # finally the key...
      ///
    s = if Buffer.isBuffer @openpgp then @openpgp.toString('utf8') else @openpgp
    if (m = s.match x)?
      @components = 
        username : m[1]
        comment : m[3]
        email : m[4]

  @make : (components) ->
    comment = if (c = components.comment)? then "(#{c}) " else ""
    openpgp = "#{components.username} #{commment}#{components.email}"
    new Userid { openpgp, components }

#=================================================================

exports.Lifespan = Lifespan
exports.Subkey = Subkey
exports.Primary = Primary
exports.UserId = UserId