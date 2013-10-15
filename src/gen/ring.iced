{Single} = require './single'
{RSA} = require './rsa'
K = require('./const').kb
{make_esc} = require 'iced-error'

#=================================================================

class UserIds
  constructor : ({@openpgp, @keybase}) ->

#=================================================================

class KeyWrapper
  constructor : ({@key, @generated, @expires}) ->

#=================================================================

class Subkey extends KeyWrapper
  constructor : ({key, @desc, generated, expires}) ->
    super { key, generated, expires }

#=================================================================

class Primary extends KeyWrapper
  constructor : ({key, generated, expires}) ->
    super { key, generated, expires }

#=================================================================

class Bundle

  constructor : ({@primary, @subkeys, @userids}) ->

  @generate : ({asp, nsubs, userids }, cb) ->
    esc = make_esc cb, "Ring::generate"
    await RSA.generate { asp, nbits: K.key_defaults.primary.nbits }, esc defer primary
    subkeys = []
    for i in [0...nsubs]
      await RSA.generate { asp, nbits: K.key_defaults.sub.nbits }, esc defer key
      subkeys.push new Subkey { key, desc : "subkey #{i}" }
    ring = new Ring { primary, subkeys, userids }
    cb null, ring

#=================================================================

exports.Bundle = Bundle
