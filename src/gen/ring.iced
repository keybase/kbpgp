{Single} = require './single'
{RSA} = require './rsa'
K = require('./const').kb
{make_esc} = require 'iced-error'

#=================================================================

class UserIds
  constructor : ({@openpgp, @keybase}) ->
    @openpgp or= "#{@keybase}@keybase.io"

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
    asp.section "primary"
    await RSA.generate { asp, nbits: K.key_defaults.primary.nbits }, esc defer primary
    subkeys = []
    for i in [0...nsubs]
      asp.section "subkey #{i+1}"
      await RSA.generate { asp, nbits: K.key_defaults.sub.nbits }, esc defer key
      subkeys.push new Subkey { key, desc : "subkey #{i}" }
    ring = new Ring { primary, subkeys, userids }
    cb null, ring


  to_openpgp_packet : ( { tsec, passphrase } ) ->

  to_keybase_packet : ( { tsec, passphrase } ) ->

#=================================================================

exports.Bundle = Bundle
