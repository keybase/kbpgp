

#=================================================================

class Subkey 
  constructor : ({@key, @desc}) ->

#=================================================================

class Ring

  constructor : ({@primary, @subkeys}) ->

#=================================================================

exports.Subkey = Subkey
exports.Ring = Ring