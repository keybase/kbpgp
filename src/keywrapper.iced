
C = require('./const')

#=================================================================

class Lifespan
  constructor : ( {@generated, @expire_in}) ->
    @expire_in or= C.default_key_expire_in

#=================================================================

class KeyWrapper
  constructor : ({@key, @lifespan}) ->

  kid : () -> @key.kid()

#=================================================================

class Subkey extends KeyWrapper
  constructor : ({key, @desc, lifespan, @primary}) -> super { key, lifespan }

#=================================================================

class Primary extends KeyWrapper
  constructor : ({key, lifespan}) -> super { key, lifespan }

#=================================================================

exports.Lifespan = Lifespan
exports.Subkey = Subkey
exports.Primary = Primary