{box} = require 'tweetnacl'
{SRF} = require '../rand'
konst = require '../const'
K = konst.kb
{bufeq_fast} = require '../util'
{BaseKey,BaseKeyPair} = require '../basekeypair'
{b2u,u2b} = require './eddsa'

TYPE = K.public_key_algorithms.NACL_DH
b2u = (b) -> new Uint8Array(b)
u2b = (u) -> new Buffer u

#=============================================

class Pub

  #--------------------


  @HEADER : new Buffer([K.kid.version, TYPE ])
  @TRAILER : new Buffer([K.kid.trailer])
  @LEN : Pub.HEADER.length + Pub.TRAILER.length + sign.publicKeyLength

  #--------------------

  constructor : (@key) ->

  #--------------------

  @alloc_kb : (kid) ->
    err = key = null
    err = if kid.length isnt Pub.LEN then new Error "bad key length"
    else if not bufeq_fast(kid[-1...], Pub.TRAILER) then new Error "bad trailing byte"
    else if not bufeq_fast(kid[0...2], Pub.HEADER) then new Error "bad header"
    else
      key = new Pub kid[2...-1]
      null
    return [ err, key ]

  #--------------------

  serialize : () -> @key
  nbits : -> 255
  read_params : (sb) ->

  #--------------------

  # Verify a signature with the given payload.
  encrypt : ({payload,sender}, cb) ->
    await SRF().random_bytes box.nonceLength, defer nonce
    res = box b2u(payload), b2u(nonce), b2u(@key), b2u(sender)
    cb null, u2b(res)

#=============================================

class Priv

  constructor : (@key) ->

  #--------------------

  alloc : (raw) ->
    err = key = null
    if raw.length isnt box.secretKeyLength
      err = new Error "Bad secret key length"
    else
      key = new Priv raw
    return [err, key]

  #--------------------

  decrypt : ({ciphertext, nonce, sender}, cb) ->
    err = res = null
    res = box.open b2u(ciphertext), b2u(nonce), b2u(sender), b2u(@key)
    if res is false
      err = new Error "decryption failed"
      res = null
    else
      res = u2b res
    cb err, res

#=============================================

class Pair extends BaseKeyPair

  construct : ({pub, priv}) -> super { pub, priv }

#=============================================

exports.DH = exports.Pair = Pair

#=============================================

