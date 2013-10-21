
C = require('./const')

#=================================================================

class Lifespan
  constructor : ( {@generated, @expire_in}) ->
    @expire_in or= C.default_key_expire_in

#=================================================================

class KeyWrapper
  constructor : ({@key, @lifespan, @_pgp, @_keybase}) ->
  kid : () -> @key.kid()
  ekid : () -> @key.ekid()

#=================================================================

class Subkey extends KeyWrapper
  constructor : ({key, _pgp, _keybase, @desc, lifespan, @primary}) -> 
    super { key, lifespan, _pgp, _keybase }

#=================================================================

class Primary extends KeyWrapper
  constructor : ({key, lifespan, _pgp, _keybase}) -> 
    super { key, lifespan, _pgp, _keybase }

#=================================================================

class UserIds
  constructor : ({@openpgp, @keybase}) ->
  get_keybase : () -> @keybase
  get_openpgp : () -> @openpgp 

#=================================================================

exports.Lifespan = Lifespan
exports.Subkey = Subkey
exports.Primary = Primary
exports.UserIds = UserIds