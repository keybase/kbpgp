{box} = require 'tweetnacl'
{SRF} = require '../rand'
konst = require '../const'
K = konst.kb
{bufeq_fast} = require '../util'
{BaseKey,BaseKeyPair} = require '../basekeypair'
NaclDh = require('./dh').Pair

TYPE = K.public_key_algorithms.NACL_EDDSA
b2u = (b) -> new Uint8Array(b)
u2b = (u) -> new Buffer u

#=============================================

class Pair extends BaseKeyPair

  construct : ({pub, priv}) -> super { pub, priv }

#=============================================

exports.DH = exports.Pair = Pair

#=============================================

