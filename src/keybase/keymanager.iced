
{KeyFetcher} = require'../keyfetch'
K = require('../const').kb
{EdDSA} = require '../nacl/eddsa'

#======================================================================

class KeyManager extends KeyFetcher

  constructor : () ->

  @generate : ({algo, params}, cb) ->
    algo or= EdDSA
    params or= {}
    await algo.generate params, defer err, key
    cb err, new KeyManager { key }

#======================================================================

