twnacl = require 'tweetnacl'
{SRF} = require '../rand'

#=============================================

class Pub

  constructor : (@key) ->
    
#=============================================

class Priv

  constructor : (@key) ->

#=============================================

class Pair

  constructor : ({@pub, @priv}) ->

  @generate : (params, cb) ->
    await SRF.random_bytes twnacl.sign.seedLength, defer seed
    {secretKey, publicKey} = twnacl.sign.keyPair.fromSeed(seed)
    pub = new Pub publicKey
    priv = new Priv secretKey
    cb null, new Pair {pub, priv}

#=============================================

exports.EdDSA = exports.Pair = Pair
